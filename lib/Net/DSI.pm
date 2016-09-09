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
use Data::Dumper;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

my $has_IO__Socket__INET6 = 0;
eval {
    require IO::Socket::INET6;
    1;
} and do {
    $has_IO__Socket__INET6 = 1;
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

    # Set up the connection to the server. Then we need to check that we've
    # connected successfully.
    my $conn;
    my %connect_args = ( PeerAddr   => $host,
                         PeerPort   => $port,
                         HostPort   => 0,
                         Proto      => 'tcp',
                         Type       => SOCK_STREAM,
                         Timeout    => 5 );
    my $handlers     = $shared->{handlers};
    my $active_timer = $params{ActiveTimer} || 60;
    my $idle_timer   = $params{IdleTimer} || 120;

    if ($has_IO__Socket__INET6 == 1) {
        $conn = new IO::Socket::INET6(%connect_args);
    }
    if (!defined($conn) || !$conn->connected()) {
        $conn = new IO::Socket::INET(%connect_args);
    }
    if (!defined($conn) || !$conn->connected()) {
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
    setsockopt($conn, IPPROTO_TCP, TCP_NODELAY, 1);
    $shared->{conn_fd}      = fileno($conn);
    $shared->{running}      = 1;
    $shared->{sockaddr}     = $conn->sockaddr();
    $shared->{sockport}     = $conn->sockport();
    $shared->{peeraddr}     = $conn->peeraddr();
    $shared->{peerport}     = $conn->peerport();
    $shared->{sockdomain}   = AF_INET;
    if (ref($conn) eq 'IO::Socket::INET6') {
        $shared->{sockdomain} = $conn->sockdomain();
    }
    $shared->{conn_sem}->up();

    # Set up a poll object for checking out our socket. Also preallocate
    # several variables which will be used in the main loop.
    my $poll = new IO::Poll;
    $poll->mask($conn, POLLIN | POLLHUP);
    my ($data, $real_length, $resp, $type, $cmd, $id, $errcode, $length,
            $reserved, $rsz, $userBytes, $ev, $now, $rb_ref, $sem_ref, $msg,
            $wsz, $handler);
    my $last_tickle     = gettimeofday();
    my $last_pkt_rcvd   = $last_tickle;
MAINLOOP:
    while ($shared->{exit} == 0) {
        $now = gettimeofday();
        # Scan the handlers list to see if there are any callouts that
        # haven't been responded to.
        keys %{$handlers};
        while (($id, $handler) = each %{$handlers}) {
            # If we find that a transaction hasn't been responded to in at
            # least $active_timer seconds (default is 60), take our ball and
            # go home.
            if (($now - $handler->[3]) > $active_timer) {
                $shared->{exit} = 1;
                print {\*STDERR} (caller(0))[3], "(): Waiting request timed out, aborting\n";
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
        if ($poll->poll(1.0)) {
            $ev = $poll->events($conn);
            if ($ev & POLLHUP) {
                # If this happens, the socket is (almost certainly) no
                # longer connected to the peer, so we should bail.
                #print {\*STDERR} (caller(0))[3], "(): Received HUP on AFP server connection, terminating loop\n";
                #last MAINLOOP;
                print {\*STDERR} (caller(0))[3], "(): poll returned POLLHUP, but this is indeterminate\n";
            }
            # Try to get a message from the server.
            $shared->{conn_sem}->down();
            $rsz = 0;
            while ($rsz < 16) {
                $length = sysread($conn, $resp, 16 - $rsz, $rsz);
                # Some kind of error occurred...
                if (!defined $length) {
                    print {\*STDERR} (caller(0))[3], "(): socket read received error $!\n";
                    $shared->{conn_sem}->up();
                    last MAINLOOP;
                }
                # This means the socket read returned EOF; we should go away.
                if ($length == 0) {
                    #print {\*STDERR} (caller(0))[3], "(): socket read returned EOF\n";
                    $shared->{conn_sem}->up();
                    last MAINLOOP;
                }
                $rsz += $length;
            }
            $shared->{conn_sem}->up();
            next MAINLOOP unless $rsz == 16;
            ($type, $cmd, $id, $errcode, $length, $reserved) =
                    unpack('CCS>l>L>L>', $resp);

            $rb_ref = *bar{SCALAR};
            $sem_ref = undef;

            $last_pkt_rcvd = gettimeofday();

            # These are requests *from* the server...
            if ($type == 0) {
                # DSICloseSession from server; this means the server is
                # going away (i.e., it's shutting down).
                if ($cmd == $OP_DSI_CLOSESESSION) {
                    #print {\*STDERR} (caller(0))[3], "(): Received CloseSession from server, setting exit flag to 1\n";
                    $shared->{exit} = 1;
                }

                elsif ($cmd == $OP_DSI_ATTENTION) {
                    $shared->{conn_sem}->down();
                    $rsz = 0;
                    while ($rsz < $length) {
                        $rsz += sysread($conn, $data, $length - $rsz, $rsz);
                        $last_pkt_rcvd = gettimeofday();
                    }
                    $shared->{conn_sem}->up();
                    ($userBytes) = unpack('n', $data);
                    # Queue the notification for later processing
                    push(@{$shared->{attnq}}, $userBytes);
                    next MAINLOOP;
                }

                elsif ($cmd == $OP_DSI_TICKLE) {
                    #print {\*STDERR} (caller(0))[3], "(): Received tickle packet at $last_pkt_rcvd\n";
                }

                else {
                    print {\*STDERR} (caller(0))[3], "(): Unexpected packet received:\n", Dumper( { type => $type, cmd => $cmd, id => $id, errcode => $errcode, length => $length, reserved =>$reserved } );
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
                    #${$$handler[0]}->up();
                    $sem_ref = $handler->[0];
                }
                else {
                    print {\*STDERR} (caller(0))[3], "(): Message packet received with id $id, but no handler block present\n";
                }
            }

            $real_length = 0;
            # Perl 5.18 gets bitchy if sysread() is passed a variable
            # containing undef.
            ${$rb_ref} = q{};
            # Get any additional data from the server, if the message
            # indicated that there was a payload.
            $shared->{conn_sem}->down();
            while ($real_length < $length) {
                $real_length += sysread($conn, ${$rb_ref},
                        $length - $real_length, $real_length);
                $last_pkt_rcvd = gettimeofday();
            }
            $shared->{conn_sem}->up();

            ${$sem_ref}->up() if defined $sem_ref;
        }

        $now = gettimeofday();
        if (($now - $last_tickle) >= 30) {
            # send a DSITickle to the server
            # Field 2: Command: DSITickle(5)
            # Manually queue the DSITickle message.
            $msg = pack('CCS>l>L>L>', 0, $OP_DSI_TICKLE,
                    $shared->{requestid}++ % 2**16, 0, 0, 0);
            $shared->{conn_sem}->down();
            $wsz = 0;
            while ($wsz < length($msg)) {
                $wsz += syswrite($conn, $msg, length($msg) - $wsz, $wsz);
            }
            $shared->{conn_sem}->up();
            $last_tickle = $now;
        }
    }
    $shared->{running} = -1;
    undef $shared->{conn_fd};
    close($conn);

    # Return $kFPNoServer to any still-waiting callers. (Sort of a hack to
    # deal with netatalk shutting down the connection right away when FPLogout
    # is received, instead of waiting for the client to send DSICloseSession.
    # Thanks again, netatalk. :| )
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
    $port ||= 548;
    my $obj = bless {}, $class;

    my $shared = &share({});
    %{$shared} = (
        # 0 means starting, 1 means running, -1 means stopped
        running     => 0,
        # set to 1 to stop the main loop
        exit        => 0,
        # a counter for a (mostly) unique sequence ID for messages
        # sent to the server.
        requestid   => 0,
        conn_fd     => undef,
        conn_sem    => new Thread::Semaphore(0),
        # completion handlers are registered here.
        handlers    => &share({}),
        # server attention messages queued here, should have
        # Net::AFP::TCP check these
        attnq       => &share([]),
    );

    $shared{id $obj}    = $shared;
    my $thread          = threads->create(\&session_thread, $shared, $host,
                                            $port);
    $dispatcher{id $obj} = $thread;
    $shared->{conn_sem}->down();
    $conn{id $obj}      = new IO::Handle;
    if ($shared->{running} == 1) {
        $conn{id $obj}->fdopen($shared->{conn_fd}, 'w');
        $conn{id $obj}->autoflush(1);
    }
    $shared->{conn_sem}->up();

    return $obj;
} # }}}1
sub close { # {{{1
    my ($self) = @_;
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

    if (defined $sem_r) {
        # Create the Thread::Semaphore object, and initialize it to 0;
        # the first down() (which will be called by whoever called us) will
        # block until up() occurs.
        $sem_r = &share($sem_r);
        ${$sem_r} = new Thread::Semaphore(0);
    }

    $resp_r  ||= *foo{SCALAR};
    $resp_r    = &share($resp_r);

    $rc_r    ||= *bar{SCALAR};
    $rc_r      = &share($rc_r);

    $message ||= q{};

    $data_r  ||= \q{};
    $d_len   ||= length(${$data_r});

    # Cycle the request ID that DSI uses to identify the request/reply
    # pairing. I'd like to handle that part asynchronously eventually.
    my $reqId  = $shared{id $self}{requestid}++ % 2**16;

    if ($shared{id $self}{running} == -1) {
        ${$sem_r}->up() if defined $sem_r;
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
    my $msg = pack('CCS>l>L>L>a*', 0, $cmd, $reqId,
            $d_len > 0 ? length($message) : 0,
            length($message) + $d_len, 0, $message);

    if (defined $sem_r) {
        my $handler = &share([]);
        @{$handler} = ( $sem_r, $resp_r, $rc_r, scalar(gettimeofday()) );
        $shared{id $self}{handlers}{$reqId} = $handler;
    }

    # Send the request packet to the server.
    $shared{id $self}{conn_sem}->down();
    my $wlen = 0;
    while ($wlen < length($msg)) {
        $wlen += syswrite($conn{id $self}, $msg, length($msg) - $wlen, $wlen);
    }
    if ($d_len) {
        $wlen = 0;
        while ($wlen < $d_len) {
            $wlen += syswrite($conn{id $self}, ${$data_r}, $d_len - $wlen,
                    $wlen);
        }
    }
    $shared{id $self}{conn_sem}->up();

    return $reqId;
} # }}}1

sub DSICloseSession { return CloseSession(@_); }
sub CloseSession { # {{{1
    my ($self) = @_;

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

    # Require that the caller provide a ref to stuff the reply block into.
    # This command is always going to provide a reply block, and the
    # information it contains is kind of important.
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
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

    my $options_packed = q{};
    foreach my $key (keys %options) {
        my $opttype;
        my $optdata;
        if ($key eq 'RequestQuanta') {
            $opttype = $kRequestQuanta;
            $optdata = pack('N', $options{$key});
        } elsif ($key eq 'AttentionQuanta') {
            $opttype = $kAttentionQuanta;
            $optdata = pack('N', $options{$key});
        } elsif ($key eq 'ServerReplayCacheSize') {
            $opttype = $kServerReplayCacheSize;
            $optdata = pack('N', $options{$key});
        } else {
            croak('Unknown option key ' . $key);
        }
        $options_packed .=  pack('CC/a*', $opttype, $optdata);
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
        my ($opttype, $optdata) = unpack('CC/a', $resp);
        if ($opttype == $kRequestQuanta) {
            $rcvd_opts{RequestQuanta}           = unpack('N', $optdata);
        } elsif ($opttype == $kAttentionQuanta) {
            $rcvd_opts{AttentionQuanta}         = unpack('N', $optdata);
        } elsif ($opttype == $kServerReplayCacheSize) {
            $rcvd_opts{ServerReplayCacheSize}   = unpack('N', $optdata);
        }
        $resp = substr($resp, 2 + length($optdata));
    }
    return wantarray ? ($rc, %rcvd_opts) : $rc;
} # }}}1

# This issues a keep-alive message to the server. This really needs to be
# done on a regular basis - hence why I want to have a separate thread to
# do dispatch duty, so it can handle things like that.
sub DSITickle { # {{{1
    my ($self) = @_;

    my $reqId = $self->SendMessage($OP_DSI_TICKLE);
    return;
} # }}}1

sub DSIWrite { return Write(@_); }
sub Write { # {{{1
    # This should only be used for FPWrite and FPAddIcon
    my ($self, $message, $data_r, $d_len, $resp_r) = @_;

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
