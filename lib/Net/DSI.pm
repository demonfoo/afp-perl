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
use Scalar::Util ();

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
use Fcntl qw(SEEK_CUR SEEK_SET);

my $do_sendfile = undef;
my %sendfile_impls = ();

eval {
    require Sys::Sendfile;
    1;
} and do {
    $sendfile_impls{q{Sys::Sendfile}} = sub {
        $_ = Sys::Sendfile::sendfile($_[1], $_[0], $_[2],
          my $off = sysseek $_[0], 0, SEEK_CUR);
        sysseek $_[0], $off + $_, SEEK_SET;
        return $_;
    };
    $do_sendfile ||= $sendfile_impls{q{Sys::Sendfile}};
};

eval {
    require Linux::PipeMagic;
    1;
} and do {
    $sendfile_impls{q{Linux::PipeMagic}} = sub {
        return Linux::PipeMagic::syssendfile($_[1], $_[0], $_[2]);
    };
    $do_sendfile ||= $sendfile_impls{q{Linux::PipeMagic}};
};

eval {
    require Sys::Syscall;
    1;
} and do {
    if (Sys::Syscall::sendfile_defined()) {
        $sendfile_impls{q{Sys::Syscall}} = sub {
            $_ = Sys::Syscall::sendfile($_[1]->fileno, $_[0]->fileno, $_[2]);
            return $_ == -1 ? undef : $_;
        };
        $do_sendfile ||= $sendfile_impls{q{Sys::Syscall}};
    }
};

eval {
    require IO::SendFile;
    1;
} and do {
    $sendfile_impls{q{IO::SendFile}} = sub {
        return IO::SendFile::sendfile($_[1]->fileno, $_[0]->fileno, $_ = 0,
          $_[2]);
    };
    $do_sendfile ||= $sendfile_impls{q{IO::SendFile}};
};

eval {
    require Sys::Sendfile::FreeBSD;
    1;
} and do {
    $sendfile_impls{q{Sys::Sendfile::FreeBSD}} = sub {
        Sys::Sendfile::FreeBSD::sendfile($_[0]->fileno, $_[1]->fileno,
          sysseek($_[0], 0, SEEK_CUR), $_[2], $_ = 0);
        sysseek $_[0], $_, SEEK_CUR;
        return $_;
    };
    $do_sendfile ||= $sendfile_impls{q{Sys::Sendfile::FreeBSD}};
};

eval {
    require Sys::Sendfile::OSX;
    1;
} and do {
    $sendfile_impls{q{Sys::Sendfile::OSX}} = sub {
        $_ = Sys::Sendfile::OSX::sendfile($_[0], $_[1], $_[2],
          sysseek $_[0], 0, SEEK_CUR);
        sysseek $_[0], $_, SEEK_CUR;
        return $_;
    };
    $do_sendfile ||= $sendfile_impls{q{Sys::Sendfile::OSX}};
};

sub import {
    my $class = shift;

    my @a;

    while (@_) {
        my $param = shift;

        # Prefer the specified sendfile wrapper module, if we imported it
        # and it's available.
        if ($param =~ m{\Asendfile_(lib|try|only)\z}sm) {
            croak qq{Library argument for import parameter ${param} is missing}
              if not  @_;
            my $libs = shift;
            croak qq{Library argument for import parameter ${param} is undefined}
              if not defined $libs;

            my @libs;
            my $overrode = 0;
            for my $lib (split m{,}sm, $libs) {
                $lib =~ s{\A\s+}{}sm;
                $lib =~ s{\s+\z}{}sm;
                push @libs, $lib;

                ##no critic qw(ProhibitEnumeratedClasses)
                if ($lib =~ m{[^a-zA-Z0-9_:]}sm) {
                    carp qq{Library name '${lib}' contains invalid characters};
                    next;
                }

                if (not CORE::length $lib) {
                    carp q{Library name is empty};
                    next;
                }

                if ($lib eq 'none') {
                    undef $do_sendfile;
                    $overrode = 1;
                    last;
                }

                if (not exists $sendfile_impls{$lib}) {
                    next;
                }

                $do_sendfile = $sendfile_impls{$lib};
                $overrode = 1;
                last;
            }
            if ($overrode == 0) {
                if ($param =~ m{_only\z}sm) {
                    croak q{Couldn't load specified sendfile lib(s) },
                      join(q{, }, map { qq{'$_'} } @libs),
                      q{, aborting};
                }
                elsif ($param =~ m{_lib\z}sm) {
                    carp q{Couldn't load specified sendfile lib(s) },
                      join(q{, }, map { qq{'$_'} } @libs),
                      q{, so using default};
                }
            }
        }
        push @a, $param;
    }
    return;
}

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
    my $logger = Log::Log4perl->get_logger();
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
    my $handlers     = ${$shared}{handlers};
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
        ${$shared}{running} = -1;
        # gotta do this so new() completes, one way or another...
        ${$shared}{conn_sem}->up();

        keys %{$handlers};
        # return $kFPNoServer for all waiting callers, and up() all the waiting
        # semaphores for them.
        while (my($id, $handler) = each %{$handlers}) {
            ${${$handler}[2]} = $kFPNoServer;
            if (defined ${$handler}[0]) {
                ${${$handler}[0]}->up();
            }
        }
        return;
    }

    # Tell the TCP stack that we don't want Nagle's algorithm; for our
    # purposes, all it's going to do is screw us up.
    $logger->debug('setting up socket and shared data');
    setsockopt $conn, IPPROTO_TCP, TCP_NODELAY, 1;
    ${$shared}{conn_fd}     = fileno $conn;
    ${$shared}{running}     = 1;
    ${$shared}{sockaddr}    = $conn->sockaddr();
    ${$shared}{sockport}    = $conn->sockport();
    ${$shared}{peeraddr}    = $conn->peeraddr();
    ${$shared}{peerport}    = $conn->peerport();
    ${$shared}{sockdomain}  = AF_INET;
    if (ref($conn) eq 'IO::Socket::IP') {
        ${$shared}{sockdomain} = $conn->sockdomain();
    }
    my $sem = ${$shared}{conn_sem};
    $sem->up();

    # Set up a poll object for checking out our socket. Also preallocate
    # several variables which will be used in the main loop.
    my $poll = IO::Poll->new();
    $poll->mask($conn, POLLIN | POLLHUP);
    my ($data, $resp, $type, $cmd, $id, $errcode, $length,
            $reserved, $rsz, $userBytes, $ev, $now, $rb_ref, $sem_ref, $msg,
            $wsz, $handler, $rlen);
    my $last_tickle     = gettimeofday();
    $logger->debug('starting DSI thread main loop');
MAINLOOP:
    while (${$shared}{exit} == 0) {
        $now = gettimeofday();
        # Scan the handlers list to see if there are any callouts that
        # haven't been responded to.
        $logger->trace('checking for unanswered handlers');
        keys %{$handlers};
        while (($id, $handler) = each %{$handlers}) {
            # If we find that a transaction hasn't been responded to in at
            # least $active_timer seconds (default is 60), take our ball and
            # go home.
            if (($now - ${$handler}[3]) > $active_timer) {
                ${$shared}{exit} = 1;
                $logger->fatal(sub { sprintf q{%s(): Waiting request timed out, aborting},
                  (caller 3)[3] });
                last MAINLOOP;
            }
        }

        if ($poll->poll(0.25)) {
            $ev = $poll->events($conn);
            if ($ev & POLLHUP) {
                # If this happens, the socket is (almost certainly) no
                # longer connected to the peer, so we should bail.
                $logger->warn(sub { sprintf q{%s(): poll returned POLLHUP, but } .
                  q{this is indeterminate}, (caller 3)[3] });
                next MAINLOOP if not $ev & ~POLLHUP;
            }
            $rb_ref = *bar{SCALAR};
            $sem_ref = undef;

            # Try to get a message from the server.
            $sem->down();
            $rsz = 0;
            while ($rsz < 16) {
                $rsz += $rlen = sysread $conn, $resp, 16 - $rsz, $rsz;
                # Some kind of error occurred...
                if (!defined $rlen) {
                    $logger->fatal(sub { sprintf q{%s(): socket read received error %d},
                      (caller 3)[3], ${ERRNO} });
                    ${$shared}{conn_sem}->up();
                    last MAINLOOP;
                }
                # This means the socket read returned EOF; we should go away.
                if ($rlen == 0) {
                    $logger->fatal(sub { sprintf q{%s(): socket read returned EOF},
                      (caller 3)[3] } );
                    ${$shared}{conn_sem}->up();
                    last MAINLOOP;
                }
            }
            if ($rsz != 16) {
                $sem->up();
                next MAINLOOP;
            }
            ($type, $cmd, $id, $errcode, $length, $reserved) =
                    unpack q{CCS>l>L>L>}, $resp;

            undef $handler;
            # These are requests *from* the server...
            if ($type == 0) {
                # DSICloseSession from server; this means the server is
                # going away (i.e., it's shutting down).
                if ($cmd == $OP_DSI_CLOSESESSION) {
                    $sem->up();
                    $logger->debug(sub { sprintf q{%s(): Received CloseSession from } .
                      q{server, setting exit flag to 1}, (caller 3)[3] });
                    ${$shared}{exit} = 1;
                }

                elsif ($cmd == $OP_DSI_ATTENTION) {
                    $rsz = 0;
                    while ($rsz < $length) {
                        $rsz += sysread $conn, $data, $length - $rsz, $rsz;
                    }
                    $sem->up();
                    ($userBytes) = unpack q{S>}, $data;
                    # Queue the notification for later processing
                    push @{${$shared}{attnq}}, $userBytes;
                    next MAINLOOP;
                }

                elsif ($cmd == $OP_DSI_TICKLE) {
                    $sem->up();
                    next MAINLOOP;
                }

                else {
                    $sem->up();
                    $logger->warn(sub { sprintf qq{%s(): Unexpected packet received:\n%s},
                      (caller 3)[3], Dumper({ type => $type, cmd => $cmd, id => $id,
                      errcode => $errcode, length => $length, reserved => $reserved }) });
                    next MAINLOOP;
                }
            } else {
                # Check for a completion handler block for the given message ID.
                if (not exists ${$handlers}{$id}) {
                    $logger->warn(sub { sprintf q{%s(): Message packet received } .
                      q{with id %d, but no handler block present}, (caller 3)[3], $id });
                }
                $handler = delete ${$handlers}{$id};
                # push the data back to the caller
                ($sem_ref, $rb_ref) = @{$handler};
                # push the return code in the message back to the caller
                # HACKHACKHACK - compat hack for netatalk
                ${${$handler}[2]} = ($errcode > 0) ? 0 : $errcode;
                # release the semaphore, after which the caller will
                # continue (if it had a semaphore, it should be blocking
                # on down())
            }

            $rsz = 0;
            # Perl 5.18 gets bitchy if sysread() is passed a variable
            # containing undef.
            ${$rb_ref} = q{};
            # Get any additional data from the server, if the message
            # indicated that there was a payload.
            while ($rsz < $length) {
                $rsz += sysread $conn, ${$rb_ref}, $length - $rsz, $rsz;
            }
            $sem->up();

            if (defined $sem_ref) {
                ${$sem_ref}->up();
            }
        }

        $now = gettimeofday();
        if (($now - $last_tickle) >= 30) {
            # send a DSITickle to the server
            # Field 2: Command: DSITickle(5)
            # Manually queue the DSITickle message.
            $msg = pack q{CCS>l>L>L>}, 0, $OP_DSI_TICKLE,
                    ${$shared}{requestid}++ % 2**16, 0, 0, 0;
            $sem->down();
            $wsz = 0;
            while ($wsz < length $msg) {
                $wsz += syswrite $conn, $msg, length($msg) - $wsz, $wsz;
            }
            $sem->up();
            $last_tickle = $now;
        }
    }
    $logger->trace('exiting main loop');
    ${$shared}{running} = -1;
    undef ${$shared}{conn_fd};
    close $conn or $logger->logcroak(q{Couldn't close the connection?});

    # Return $kFPNoServer to any still-waiting callers. (Sort of a hack to
    # deal with netatalk shutting down the connection right away when FPLogout
    # is received, instead of waiting for the client to send DSICloseSession.
    # Thanks again, netatalk. :| )
    $logger->trace('cleaning up any pending handlers');
    keys %{$handlers};
    while (($id, $handler) = each %{$handlers}) {
        $handler = ${$handlers}{$id};
        ${${$handler}[2]} = $kFPNoServer;
        if (defined ${$handler}[0]) {
            ${${$handler}[0]}->up();
        }
    }
    return;
} # }}}1

sub new { # {{{1
    my ($class, $host, $port, %params) = @_;
    my $logger          = Log::Log4perl->get_logger();
    $port             ||= 548;
    my $obj = bless {}, $class;
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $shared           = shared_clone({});
    %{$shared}           = (
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
        sems        => shared_clone([]),
    );

    $shared{id $obj}     = $shared;
    $logger->debug('starting session_thread');
    my $thread           = threads->create(\&session_thread, $shared, $host,
                                             $port, %params);
    $dispatcher{id $obj} = $thread;
    ${$shared}{conn_sem}->down();
    $conn{id $obj}       = IO::Handle->new();
    if (${$shared}{running} == 1) {
        $conn{id $obj}->fdopen(${$shared}{conn_fd}, 'w');
        $conn{id $obj}->autoflush(1);
    }
    ${$shared}{conn_sem}->up();

    return $obj;
} # }}}1

##no critic qw(ProhibitAmbiguousNames ProhibitBuiltinHomonyms)
sub close { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger();
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
##no critic qw(ProhibitManyArgs RequireArgUnpacking)
sub SendMessage { # {{{1
    my ($self, $cmd, $message, $data_r, $d_len, $sem, $resp_r, $rc, $from_fh) = @_;
    #my $logger = Log::Log4perl->get_logger();
    #$logger->debug(sub { sprintf q{called %s()}, (caller(3))[3] });

    my $ourshared = $shared{id $self};
    if (not Scalar::Util::readonly($_[5])) {
        # Get a semaphore and reuse it if we can; create one if not. This
        # gets used to notify the caller that their request has been
        # completed.
        share($_[5]);
        $_[5] = shift @{${$ourshared}{sems}};
        if (not defined $_[5]) {
            $_[5] = Thread::Semaphore->new(0);
        }
    }

    $resp_r  ||= *foo{SCALAR};
    share($resp_r);

    if (not Scalar::Util::readonly($_[7])) {
        share($_[7]);
    }

    $message ||= q{};

    if (not defined $data_r) {
        # so it seems it gets the same scalar back; we need to make it empty.
        ${$data_r = *baz{SCALAR}} = q{};
    }
    $d_len   ||= length ${$data_r} || 0;

    # Cycle the request ID that DSI uses to identify the request/reply
    # pairing. I'd like to handle that part asynchronously eventually.
    my $reqId;
    do {
        $reqId = ${$ourshared}{requestid}++ % 2**16;
    ##no critic qw(ProhibitPostfixControls)
    } while (exists ${$ourshared}{handlers}{$reqId});

    if (${$ourshared}{running} == -1) {
        if (defined $_[5]) {
            $_[5]->up();
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
    my $msg = pack q{CCS>l>L>L>a*}, 0, $cmd, $reqId,
            $d_len > 0 ? length($message) : 0,
            length($message) + $d_len, 0, $message;

    if (defined $_[5]) {
        # shared_clone() is slower, because it tries to walk it.
        my $handler = [];
        share(@{$handler});
        @{$handler} = ( \$_[5], $resp_r, \$_[7], scalar gettimeofday() );
        ${$ourshared}{handlers}{$reqId} = $handler;
    }

    # Send the request packet to the server.
    ${$ourshared}{conn_sem}->down();
    my $wlen = 0;
    while ($wlen < length $msg) {
        $wlen += syswrite $conn{id $self}, $msg, length($msg) - $wlen, $wlen;
    }
    if ($d_len) {
        if (defined $from_fh) {
            undef $wlen;
            if (defined $do_sendfile) {
                $wlen = &{$do_sendfile}($from_fh, $conn{id $self}, $d_len);

                goto FINISHED if defined $wlen;
                # if the above doesn't happen, sendfile failed, so I guess
                # let's not do that again.
                undef $do_sendfile;
            }

            # uh, so there's no sendfile option available to us... so I
            # guess we have to just read it ourselves, and write it anyway.
            # I don't like it, but we seem to be out of options.
            sysread $from_fh, ${$data_r}, $d_len;
        }
        $wlen = 0;
        while ($wlen < $d_len) {
            $wlen += syswrite $conn{id $self}, ${$data_r}, $d_len - $wlen,
              $wlen;
        }
    }
FINISHED:
    ${$ourshared}{conn_sem}->up();

    return $reqId;
} # }}}1

sub CloseSession { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    # Issue the DSICloseSession command to the server. Apparently the
    # server doesn't have anything to say in response.
    my $reqId = $self->SendMessage($OP_DSI_CLOSESESSION);
    return;
} # }}}1

sub Command { # {{{1
    my ($self, $message, $resp_r) = @_;

    # Require that the caller includes a reference to stuff a reply block
    # into - issuing a DSICommand generally gets one.
    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_COMMAND, $message, undef, undef,
            $sem, $resp_r, $rc);
    $sem->down();
    push @{$shared{id $self}{sems}}, $sem;
    return $reqId < 0 ? $reqId : $rc;
} # }}}1

sub GetStatus { # {{{1
    my ($self, $resp_r) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    # Require that the caller provide a ref to stuff the reply block into.
    # This command is always going to provide a reply block, and the
    # information it contains is kind of important.
    if (ref($resp_r) ne q{SCALAR} and ref($resp_r) ne q{REF}) {
        $logger->logcroak(q{resp_r must be a scalar ref});
    }
    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_GETSTATUS, undef, undef, undef,
            $sem, $resp_r, $rc);
    $sem->down();
    push @{$shared{id $self}{sems}}, $sem;
    return $reqId < 0 ? $reqId : $rc;
} # }}}1

my @OpenSessionOpts = (
    {
        value  => $kRequestQuanta,
        fields => ['RequestQuanta'],
        mask   => q{L>},
        len    => 4,
    },
    {
        value  => $kAttentionQuanta,
        fields => ['AttentionQuanta'],
        mask   => q{L>},
        len    => 4,
    },
    {
        value  => $kServerReplayCacheSize,
        fields => ['ServerReplayCacheSize'],
        mask   => q{L>},
        len    => 4,
    },
);

# transform to hashes indexed by numeric value and keys
## no critic qw(ProhibitCommaSeparatedStatements)
my %osoptsbyvalue = map { ${$_}{value}, $_ } @OpenSessionOpts;
## no critic qw(ProhibitCommaSeparatedStatements)
my %osoptsbyfield = map { ${$_}{fields}[0], $_ } @OpenSessionOpts;

sub OpenSession { # {{{1
    my ($self, %options) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my @options_packed;
    foreach my $key (keys %options) {
        if (not exists $osoptsbyfield{$key}) {
            $logger->logconfess(sprintf q{Unknown option key "%s"}, $key);
        }
        my $item = $osoptsbyfield{$key};
        push @options_packed, pack q{CC/a}, ${$item}{value},
          pack ${$item}{mask}, $options{$key};
    }

    my $sem;
    my $rc;
    my $resp;
    my $reqId = $self->SendMessage($OP_DSI_OPENSESSION,
      join(q{}, @options_packed), undef, undef, $sem, \$resp, $rc);
    return $reqId if $reqId < 0;
    $sem->down();
    push @{$shared{id $self}{sems}}, $sem;

    my %rcvd_opts;
    my @opts = unpack q{(CC/a)*}, $resp;
    while (my($type, $data) = splice @opts, 0, 2) {
        if (not exists $osoptsbyvalue{$type}) {
            $logger->logconfess(sprintf q{Unknown value type %d from server}, $type);
        }
        my $item = $osoptsbyvalue{$type};
        @rcvd_opts{@{${$item}{fields}}} = unpack ${$item}{mask}, $data;
    }
    return wantarray ? ($rc, %rcvd_opts) : $rc;
} # }}}1

# This issues a keep-alive message to the server. This really needs to be
# done on a regular basis - hence why I want to have a separate thread to
# do dispatch duty, so it can handle things like that.
sub Tickle { # {{{1
    my ($self) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $reqId = $self->SendMessage($OP_DSI_TICKLE);
    return;
} # }}}1

sub Write { # {{{1
    # This should only be used for FPWrite and FPAddIcon
    my ($self, $message, $data_r, $d_len, $resp_r, $from_fh) = @_;
    #my $logger = Log::Log4perl->get_logger();
    #$logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $sem;
    my $rc;
    my $reqId = $self->SendMessage($OP_DSI_WRITE, $message, $data_r, $d_len,
            $sem, $resp_r, $rc, $from_fh);
    return $reqId if $reqId < 0;
    $sem->down();
    push @{$shared{id $self}{sems}}, $sem;
    return $rc;
} # }}}1

1;
# vim: ts=4 fdm=marker ai et sw=4
