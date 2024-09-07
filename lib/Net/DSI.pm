# This is Net::DSI. It is an implementation of the DSI shim
# protocol that acts as a mid-layer between AFP and TCP protocols. This
# implementation is fairly complete; it doesn't properly handle server
# notifications, but otherwise it handles pretty much everything worth
# caring about.
package Net::DSI;

use strict;
use warnings;
use diagnostics;
use integer;
use Log::Log4perl;
use Data::Dumper;
use English qw(-no_match_vars);

# Enables a nice call trace on warning events.
use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

my $has_IO__Socket__IP = 0;
eval {
    require IO::Socket::IP;
    1;
} and do {
    $has_IO__Socket__IP = 1;
};
use IO::Socket::INET;
use IO::Poll qw(POLLIN POLLHUP);
use IO::Handle;
use Net::AFP::Result;
use Time::HiRes qw(gettimeofday);
use threads;
use threads::shared;
use Thread::Semaphore;
use Socket qw(TCP_NODELAY IPPROTO_TCP);
use Readonly;
use Class::InsideOut qw(public readonly private register id);

Readonly my $OP_DSI_CLOSESESSION        => 1;   # to and from server
Readonly my $OP_DSI_COMMAND             => 2;   # to server only
Readonly my $OP_DSI_GETSTATUS           => 3;   # to server only
Readonly my $OP_DSI_OPENSESSION         => 4;   # to server only
Readonly my $OP_DSI_TICKLE              => 5;   # to and from server
Readonly my $OP_DSI_WRITE               => 6;   # to server only
Readonly my $OP_DSI_ATTENTION           => 8;   # from server only

Readonly our $kRequestQuanta            => 0x00;
# not sure if this is the canonical name for this option code...
Readonly our $kAttentionQuanta          => 0x01;
Readonly our $kServerReplayCacheSize    => 0x02;

private     dispatcher  => my %dispatcher;
private     conn        => my %conn;
private     shared      => my %shared;

# This function is the body of our thread. It's a hybrid dispatcher
# arrangement, and it will also send periodic (~30 second interval)
# keepalive messages to the server side. $shared will contain a shared
# data structure containing completion handler blocks, with references
# to return data to callers, and completion notifications handled via
# Thread::Semaphore objects. It also contains a 'running' flag, to
# allow potential callers to know if the thread is in play or not.
sub session_thread { # {{{1
    my($shared, $host, $port, %params) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    # Set up the connection to the server. Then we need to check that we've
    # connected successfully.
    my $conn;
    my %connect_args = (
        PeerAddr   => $host,
        PeerPort   => $port,
        HostPort   => 0,
        Proto      => 'tcp',
        Type       => SOCK_STREAM,
        Timeout    => 5,
    );
    my $handlers     = $shared->{handlers};
    my $active_timer = $params{ActiveTimer} || 60;
    my $idle_timer   = $params{IdleTimer} || 120;

    $logger->debug('connecting to AFP server');
    if ($has_IO__Socket__IP == 1) {
        $conn = IO::Socket::IP->new(%connect_args);
    }
    if (!defined($conn) || !$conn->connected()) {
        $conn = IO::Socket::INET->new(%connect_args);
    }
    if (!defined($conn) || !$conn->connected()) {
        $logger->debug('connection attempt failed, aborting');
        $shared->{running} = -1;
        # gotta do this so new() completes, one way or another...
        $shared->{conn_sem}->up();

        keys %{$handlers};
        # return $kFPNoServer for all waiting callers, and up() all the waiting
        # semaphores for them.
        while (my($id, $handler) = each %{$handlers}) {
            ${$handler->[2]} = $kFPNoServer;
            ${$handler->[0]}->up();
        }
        return;
    }

    # Tell the TCP stack that we don't want Nagle's algorithm; for our
    # purposes, all it's going to do is screw us up.
    $logger->debug('setting up socket and shared data');
    setsockopt $conn, IPPROTO_TCP, TCP_NODELAY, 1;
    $shared->{conn_fd}      = fileno $conn;
    $shared->{running}      = 1;
    $shared->{sockaddr}     = $conn->sockaddr();
    $shared->{sockport}     = $conn->sockport();
    $shared->{peeraddr}     = $conn->peeraddr();
    $shared->{peerport}     = $conn->peerport();
    $shared->{sockdomain}   = AF_INET;
    if (ref($conn) eq 'IO::Socket::IP') {
        $shared->{sockdomain} = $conn->sockdomain();
    }
    $shared->{conn_sem}->up();

    # Set up a poll object for checking out our socket. Also preallocate
    # several variables which will be used in the main loop.
    my $poll = IO::Poll->new();
    $poll->mask($conn, POLLIN | POLLHUP);
    my ($data, $resp, $type, $cmd, $id, $errcode, $length,
            $reserved, $rsz, $userBytes, $ev, $now, $rb_ref, $sem_ref, $msg,
            $wsz, $handler, $rlen);
    my $last_tickle     = gettimeofday();
    my $last_pkt_rcvd   = $last_tickle;
    $logger->debug('starting DSI thread main loop');
MAINLOOP:
    while ($shared->{exit} == 0) {
        $now = gettimeofday();
        # Scan the handlers list to see if there are any callouts that
        # haven't been responded to.
        #$logger->debug('checking for unanswered handlers');
        keys %{$handlers};
        while (($id, $handler) = each %{$handlers}) {
            # If we find that a transaction hasn't been responded to in at
            # least $active_timer seconds (default is 60), take our ball and
            # go home.
            if (($now - $handler->[3]) > $active_timer) {
                $shared->{exit} = 1;
                $logger->fatal(sub { sprintf q{%s(): Waiting request timed out, aborting},
                  (caller 3)[3] });
                last MAINLOOP;
            }
        }

        # Check to see how long it's been since we've heard a tickle packet
        # from the server...
        #if ($now - $last_pkt_rcvd > $idle_timer) {
            # Apple's docs say if we are 2 minutes out from receiving a
            # tickle from the peer, we should assume the connection is
            # dead.
        #    print {\*STDERR} (caller(0))[3], "(): No packets in 120 seconds, setting exit flag to 1\n";
        #    $shared->{exit} = 1;
        #    last;
        #}
        if ($poll->poll(0.25)) {
            $ev = $poll->events($conn);
            if ($ev & POLLHUP) {
                # If this happens, the socket is (almost certainly) no
                # longer connected to the peer, so we should bail.
                #print {\*STDERR} (caller(0))[3], "(): Received HUP on AFP server connection, terminating loop\n";
                #last MAINLOOP;
                $logger->warn(sub { sprintf q{%s(): poll returned POLLHUP, but } .
                  q{this is indeterminate}, (caller 3)[3] });
            }
            # Try to get a message from the server.
            #$logger->debug('reading from socket');
            $shared->{conn_sem}->down();
            $rsz = 0;
            while ($rsz < 16) {
                $rsz += $rlen = sysread $conn, $resp, 16 - $rsz, $rsz;
                # Some kind of error occurred...
                if (!defined $rlen) {
                    $logger->fatal(sub { sprintf q{%s(): socket read received error %d},
                      (caller 3)[3], ${ERRNO} });
                    $shared->{conn_sem}->up();
                    last MAINLOOP;
                }
                # This means the socket read returned EOF; we should go away.
                if ($rlen == 0) {
                    $logger->fatal(sub { sprintf q{%s(): socket read returned EOF},
                      (caller 3)[3] } );
                    $shared->{conn_sem}->up();
                    last MAINLOOP;
                }
            }
            $shared->{conn_sem}->up();
            next MAINLOOP if $rsz != 16;
            ($type, $cmd, $id, $errcode, $length, $reserved) =
                    unpack 'CCS>l>L>L>', $resp;

            $rb_ref = *bar{SCALAR};
            $sem_ref = undef;

            $last_pkt_rcvd = gettimeofday();

            # These are requests *from* the server...
            if ($type == 0) {
                # DSICloseSession from server; this means the server is
                # going away (i.e., it's shutting down).
                if ($cmd == $OP_DSI_CLOSESESSION) {
                    $logger->debug(sub { sprintf q{%s(): Received CloseSession from } .
                      q{server, setting exit flag to 1}, (caller 3)[3] });
                    $shared->{exit} = 1;
                }

                elsif ($cmd == $OP_DSI_ATTENTION) {
                    $shared->{conn_sem}->down();
                    $rsz = 0;
                    while ($rsz < $length) {
                        $rsz += $rlen = sysread $conn, $data, $length - $rsz, $rsz;
                    }
                    $last_pkt_rcvd = gettimeofday();
                    $shared->{conn_sem}->up();
                    ($userBytes) = unpack 'S>', $data;
                    # Queue the notification for later processing
                    push @{$shared->{attnq}}, $userBytes;
                    next MAINLOOP;
                }

                elsif ($cmd == $OP_DSI_TICKLE) {
                    #print {\*STDERR} (caller(0))[3], "(): Received tickle packet at $last_pkt_rcvd\n";
                }

                else {
                    $logger->warn(sub { sprintf qq{%s(): Unexpected packet received:\n%s},
                      (caller 3)[3], Dumper({ type => $type, cmd => $cmd, id => $id,
                      errcode => $errcode, length => $length, reserved => $reserved }) });
                }
            } else {
                # Check for a completion handler block for the given message ID.
                if (exists $handlers->{$id}) {
                    $handler = $handlers->{$id};
                    delete $handlers->{$id};
                    # push the data back to the caller
                    #${$handler->[1]} = ($length ? $data : '');
                    $rb_ref = $handler->[1];
                    # push the return code in the message back to the caller
                    # HACKHACKHACK - compat hack for netatalk
                    ${$handler->[2]} = ($errcode > 0) ? 0 : $errcode;
                    # release the semaphore, after which the caller will
                    # continue (if it had a semaphore, it should be blocking
                    # on down())
                    $sem_ref = $handler->[0];
                }
                else {
                    $logger->warn(sub { sprintf q{%s(): Message packet received } .
                      q{with id %d, but no handler block present}, (caller 3)[3], $id });
                }
            }

            $rsz = 0;
            # Perl 5.18 gets bitchy if sysread() is passed a variable
            # containing undef.
            ${$rb_ref} = q{};
            # Get any additional data from the server, if the message
            # indicated that there was a payload.
            $shared->{conn_sem}->down();
            while ($rsz < $length) {
                $rsz += $rlen = sysread $conn, ${$rb_ref},
                        $length - $rsz, $rsz;
            }
            $last_pkt_rcvd = gettimeofday();
            $shared->{conn_sem}->up();

            if (defined $sem_ref) {
                ${$sem_ref}->up();
            }
        }

        $now = gettimeofday();
        if (($now - $last_tickle) >= 30) {
            # send a DSITickle to the server
            # Field 2: Command: DSITickle(5)
            # Manually queue the DSITickle message.
            $msg = pack 'CCS>l>L>L>', 0, $OP_DSI_TICKLE,
                    $shared->{requestid}++ % 2**16, 0, 0, 0;
            $shared->{conn_sem}->down();
            $wsz = 0;
            while ($wsz < length $msg) {
                $wsz += syswrite $conn, $msg, length($msg) - $wsz, $wsz;
            }
            $shared->{conn_sem}->up();
            $last_tickle = $now;
        }
    }
    $logger->debug('exiting main loop');
    $shared->{running} = -1;
    undef $shared->{conn_fd};
    close $conn;

    # Return $kFPNoServer to any still-waiting callers. (Sort of a hack to
    # deal with netatalk shutting down the connection right away when FPLogout
    # is received, instead of waiting for the client to send DSICloseSession.
    # Thanks again, netatalk. :| )
    $logger->debug('cleaning up any pending handlers');
    keys %{$handlers};
    while (($id, $handler) = each %{$handlers}) {
        $handler = $handlers->{$id};
        ${$handler->[2]} = $kFPNoServer;
        ${$handler->[0]}->up();
    }
    return;
} # }}}1

sub new { # {{{1
    my ($class, $host, $port, %params) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $port ||= 548;
    my $obj = bless {}, $class;
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $shared = shared_clone({});
    %{$shared} = (
        # 0 means starting, 1 means running, -1 means stopped
        running     => 0,
        # set to 1 to stop the main loop
        exit        => 0,
        # a counter for a (mostly) unique sequence ID for messages
        # sent to the server.
        requestid   => 0,
        conn_fd     => undef,
        conn_sem    => Thread::Semaphore->new(0),
        # completion handlers are registered here.
        handlers    => shared_clone({}),
        # server attention messages queued here, should have
        # Net::AFP::TCP check these
        attnq       => shared_clone([]),
        #logger      => $logger,
    );

    $shared{id $obj}    = $shared;
    $logger->debug('starting session_thread');
    my $thread          = threads->create(\&session_thread, $shared, $host,
                                            $port);
    $dispatcher{id $obj} = $thread;
    $shared->{conn_sem}->down();
    $conn{id $obj}      = IO::Handle->new();
    if ($shared->{running} == 1) {
        $conn{id $obj}->fdopen($shared->{conn_fd}, 'w');
        $conn{id $obj}->autoflush(1);
    }
    $shared->{conn_sem}->up();

    return $obj;
} # }}}1

sub close { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });
    $shared{id $self}{exit} = 1;
    $dispatcher{id $self}->join();
    return;
} # }}}1

# Arguments:
#   $self:      A Net::DSI instance.
#   $cmd:       The numeric opcode of the command we wish to issue to the DSI
#               server.
#   $message:   The message payload, if any, to send with the command. Many
#               of the command opcodes don't take any payload.
#   $data_r:    Reference to additional data outside the payload to include
#               in the sent message; only used for DSIWrite operation.
#   $sem_r:     A reference to contain a Thread::Semaphore object which can
#               be used to determine when a response has been received. If
#               no response is expected, should be undef.
#   $resp_r:    A reference to a scalar, which will be made shared and will
#               receive the response when one is received. If no response is
#               expected, this should be undef.
#   $rc_r:      A reference to a scalar, which will be made shared and will
#               receive the return code from the callout. If no response is
#               desired, this should be undef.
sub SendMessage { # {{{1
    my ($self, $cmd, $message, $data_r, $d_len, $sem_r, $resp_r, $rc_r) = @_;
    #my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    #$logger->debug(sub { sprintf q{called %s()}, (caller(3))[3] });

    if (defined $sem_r) {
        # Create the Thread::Semaphore object, and initialize it to 0;
        # the first down() (which will be called by whoever called us) will
        # block until up() occurs.
        share($sem_r);
        ${$sem_r} = Thread::Semaphore->new(0);
    }

    $resp_r  ||= *foo{SCALAR};
    share($resp_r);

    $rc_r    ||= *bar{SCALAR};
    share($rc_r);

    $message ||= q{};

    $data_r  ||= \q{};
    $d_len   ||= length ${$data_r};

    # Cycle the request ID that DSI uses to identify the request/reply
    # pairing. I'd like to handle that part asynchronously eventually.
    my $reqId  = $shared{id $self}{requestid}++ % 2**16;

    if ($shared{id $self}{running} == -1) {
        if (defined $sem_r) {
            ${$sem_r}->up();
        }
        return $kFPNoServer;
    }
    # Assemble the message header to be sent to the AFP over TCP server.
    # Arg 1: byte  Flags: 0 for request, 1 for reply
    # Arg 2: byte  Command
    # Arg 3: short RequestID
    # Arg 4: long  ErrCode: should be 0 for requests, should contain the
    #        data offset for DSIWrite messages
    # Arg 5: long  MsgLength
    # Arg 6: long  Reserved: 0
    my $msg = pack 'CCS>l>L>L>a*', 0, $cmd, $reqId,
            $d_len > 0 ? length($message) : 0,
            length($message) + $d_len, 0, $message;

    if (defined $sem_r) {
        my $handler = shared_clone([]);
        @{$handler} = ( $sem_r, $resp_r, $rc_r, scalar gettimeofday() );
        $shared{id $self}{handlers}{$reqId} = $handler;
    }

    # Send the request packet to the server.
    $shared{id $self}{conn_sem}->down();
    my $wlen = 0;
    while ($wlen < length $msg) {
        $wlen += syswrite $conn{id $self}, $msg, length($msg) - $wlen, $wlen;
    }
    if ($d_len) {
        $wlen = 0;
        while ($wlen < $d_len) {
            $wlen += syswrite $conn{id $self}, ${$data_r}, $d_len - $wlen,
                    $wlen;
        }
    }
    $shared{id $self}{conn_sem}->up();

    return $reqId;
} # }}}1

sub DSICloseSession { return CloseSession(@_); }
sub CloseSession { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    # Issue the DSICloseSession command to the server. Apparently the
    # server doesn't have anything to say in response.
    my $reqId = $self->SendMessage($OP_DSI_CLOSESESSION);
    return;
} # }}}1

sub DSICommand { return Command(@_); }
sub Command { # {{{1
    my ($self, $message, $resp_r) = @_;

    # Require that the caller includes a reference to stuff a reply block
    # into - issuing a DSICommand generally gets one.
    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_COMMAND, $message, undef, undef,
            \$sem, $resp_r, \$rc);
    $sem->down();
    return $reqId if $reqId < 0;

    return $rc;
} # }}}1

sub DSIGetStatus { return GetStatus(@_); }
sub GetStatus { # {{{1
    my ($self, $resp_r) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    # Require that the caller provide a ref to stuff the reply block into.
    # This command is always going to provide a reply block, and the
    # information it contains is kind of important.
    croak('resp_r must be a scalar ref')
            if ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF';
    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_GETSTATUS, undef, undef, undef,
            \$sem, $resp_r, \$rc);
    $sem->down();
    return $reqId if $reqId < 0;

    return $rc;
} # }}}1

sub DSIOpenSession { return OpenSession(@_); }
sub OpenSession { # {{{1
    my ($self, %options) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $options_packed = q{};
    foreach my $key (keys %options) {
        my $opttype;
        my $optdata;
        if ($key eq 'RequestQuanta') {
            $opttype = $kRequestQuanta;
            $optdata = pack 'L>', $options{$key};
        } elsif ($key eq 'AttentionQuanta') {
            $opttype = $kAttentionQuanta;
            $optdata = pack 'L>', $options{$key};
        } elsif ($key eq 'ServerReplayCacheSize') {
            $opttype = $kServerReplayCacheSize;
            $optdata = pack 'L>', $options{$key};
        } else {
            croak('Unknown option key ' . $key);
        }
        $options_packed .=  pack 'CC/a*', $opttype, $optdata;
    }

    my $sem;
    my $rc;
    my $resp;
    my $reqId = $self->SendMessage($OP_DSI_OPENSESSION, $options_packed, undef,
            undef, \$sem, \$resp, \$rc);
    return $reqId if $reqId < 0;
    $sem->down();

    my %rcvd_opts;
    while (length($resp) > 0) {
        my ($opttype, $optdata) = unpack 'CC/a', $resp;
        if ($opttype == $kRequestQuanta) {
            $rcvd_opts{RequestQuanta}           = unpack 'L>', $optdata;
        } elsif ($opttype == $kAttentionQuanta) {
            $rcvd_opts{AttentionQuanta}         = unpack 'L>', $optdata;
        } elsif ($opttype == $kServerReplayCacheSize) {
            $rcvd_opts{ServerReplayCacheSize}   = unpack 'L>', $optdata;
        }
        $resp = substr $resp, 2 + length $optdata;
    }
    return wantarray ? ($rc, %rcvd_opts) : $rc;
} # }}}1

# This issues a keep-alive message to the server. This really needs to be
# done on a regular basis - hence why I want to have a separate thread to
# do dispatch duty, so it can handle things like that.
sub DSITickle { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $reqId = $self->SendMessage($OP_DSI_TICKLE);
    return;
} # }}}1

sub DSIWrite { return Write(@_); }
sub Write { # {{{1
    # This should only be used for FPWrite and FPAddIcon
    my ($self, $message, $data_r, $d_len, $resp_r) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_WRITE, $message, $data_r, $d_len,
            \$sem, $resp_r, \$rc);
    return $reqId if $reqId < 0;
    $sem->down();
    return $rc;
} # }}}1

1;
# vim: ts=4 fdm=marker ai et
