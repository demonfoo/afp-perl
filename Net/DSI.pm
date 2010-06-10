# This is Net::DSI. It is an implementation of the DSI shim
# protocol that acts as a mid-layer between AFP and TCP protocols. This
# implementation is fairly complete; it doesn't properly handle server
# notifications, but otherwise it handles pretty much everything worth
# caring about.
package Net::DSI;

my $has_IO__Socket__INET6 = 1;
eval { require IO::Socket::INET6; };
if ($@) {
	$has_IO__Socket__INET6 = 0;
}
use IO::Socket::INET;
use IO::Poll qw(POLLIN POLLHUP);
use IO::Handle;
use Net::AFP::Result;
use Time::HiRes qw(gettimeofday);
use threads;
use threads::shared;
use Thread::Semaphore;
use Socket qw(TCP_NODELAY IPPROTO_TCP);
use strict;
use warnings;

=head1 NAME

Net::DSI - Object interface for Apple Data Stream Interface protocol

=head1 SYNOPSIS

    use Net::DSI;

=head1 DESCRIPTION

C<Net::DSI> provides an object-based interface to interacting with
Data Stream Interface-based services, specifically AFP over TCP. The
protocol acts as a mid-layer between the bidirectional stream semantics
provided by TCP, and the transactional interface AFP requires.

=cut

use constant OP_DSI_CLOSESESSION	=> 1;	# to and from server
use constant OP_DSI_COMMAND			=> 2;	# to server only
use constant OP_DSI_GETSTATUS		=> 3;	# to server only
use constant OP_DSI_OPENSESSION		=> 4;	# to server only
use constant OP_DSI_TICKLE			=> 5;	# to and from server
use constant OP_DSI_WRITE			=> 6;	# to server only
use constant OP_DSI_ATTENTION		=> 8;	# from server only

use constant kRequestQuanta			=> 0x00;
# not sure if this is the canonical name for this option code...
use constant kAttentionQuanta		=> 0x01;
use constant kServerReplayCacheSize	=> 0x02;

# This function is the body of our thread. It's a hybrid dispatcher
# arrangement, and it will also send periodic (~30 second interval)
# keepalive messages to the server side. $shared will contain a shared
# data structure containing completion handler blocks, with references
# to return data to callers, and completion notifications handled via
# Thread::Semaphore objects. It also contains a 'running' flag, to
# allow potential callers to know if the thread is in play or not.
sub session_thread { # {{{1
	my($shared, $host, $port) = @_;

	# Set up the connection to the server. Then we need to check that we've
	# connected successfully.
	my $conn;
	my %connect_args = ( 'PeerAddr'		=> $host,
						 'PeerPort'		=> $port,
						 'HostPort'		=> 0,
						 'Proto'		=> 'tcp',
						 'Type'			=> SOCK_STREAM );
	if ($has_IO__Socket__INET6 == 1) {
		$conn = new IO::Socket::INET6(%connect_args);
	}
	if (!defined($conn) || !$conn->connected()) {
		$conn = new IO::Socket::INET(%connect_args);
	}
	my $handler;
	unless (defined $conn and $conn->connected()) {
		$$shared{'running'} = -1;
		# gotta do this so new() completes, one way or another...
		$$shared{'conn_sem'}->up();

		# return kFPNoServer for all waiting callers, and up() all the waiting
		# semaphores for them.
		foreach my $id (keys %{$$shared{'handlers'}}) {
			$handler = $$shared{'handlers'}{$id};
			${$$handler[2]} = kFPNoServer;
			${$$handler[0]}->up();
		}
		return;
	}

	# Tell the TCP stack that we don't want Nagle's algorithm; for our
	# purposes, all it's going to do is screw us up.
	setsockopt($conn, IPPROTO_TCP, TCP_NODELAY, 1);
	$$shared{'conn_fd'} = fileno($conn);
	$$shared{'running'} = 1;
	$$shared{'sockaddr'} = $conn->sockaddr();
	$$shared{'sockport'} = $conn->sockport();
	$$shared{'peeraddr'} = $conn->peeraddr();
	$$shared{'peerport'} = $conn->peerport();
	$$shared{'sockdomain'} = AF_INET;
	if (ref($conn) eq 'IO::Socket::INET6') {
		$$shared{'sockdomain'} = $conn->sockdomain();
	}
	$$shared{'conn_sem'}->up();

	# Set up a poll object for checking out our socket. Also preallocate
	# several variables which will be used in the main loop.
	my $poll = new IO::Poll;
	$poll->mask($conn, POLLIN | POLLHUP);
	my ($data, $real_length, $resp, $type, $cmd, $id, $errcode, $length,
			$reserved, $rsz, $userBytes, $ev, $now);
	my $last_tickle = 0;
MAINLOOP:
	while ($$shared{'exit'} == 0) {
		if ($poll->poll(0.5)) {
			$ev = $poll->events($conn);
			if ($ev & POLLHUP) {
				# If this happens, the socket is (almost certainly) no
				# longer connected to the peer, so we should bail.
				last MAINLOOP;
			}
			# Try to get a message from the server.
			$rsz = sysread($conn, $resp, 16);
			last MAINLOOP unless defined $rsz;
			next MAINLOOP unless $rsz == 16;
			($type, $cmd, $id, $errcode, $length, $reserved) =
					unpack('CCnNNN', $resp);
	
			$real_length = 0;
			# Get any additional data from the server, if the message
			# indicated that there was a payload.
			until ($real_length >= $length) {
				$real_length += sysread($conn, $data, $length - $real_length,
						$real_length);
			}

			if ($type == 0) {
				# DSICloseSession from server; this means the server is
				# going away (i.e., it's shutting down).
				if ($cmd == OP_DSI_CLOSESESSION) {
					$$shared{'exit'} = 1;
				}

				elsif ($cmd == OP_DSI_ATTENTION) {
					($userBytes) = unpack('n', $data);
					# Queue the notification for later processing
					push(@{$$shared{'attnq'}}, $userBytes);
				}
			} else {
				# Handle negative return codes in the canonical way.
				if ($errcode & 0x80000000) {
					$errcode = -((~$errcode & 0xFFFFFFFF) + 1);
				}

				# Check for a completion handler block for the given message ID.
				if (exists $$shared{'handlers'}{$id}) {
					$handler = $$shared{'handlers'}{$id};
					delete $$shared{'handlers'}{$id};
					# push the data back to the caller
					${$$handler[1]} = $data;
					# push the return code in the message back to the caller
					# HACKHACKHACK - compat hack for netatalk
					${$$handler[2]} = ($errcode > 0) ? 0 : $errcode;
					# release the semaphore, after which the caller will
					# continue (if it had a semaphore, it should be blocking
					# on down())
					${$$handler[0]}->up();
				}
			}
		}

		$now = time();
		if (($now - $last_tickle) >= 30) {
			# send a DSITickle to the server
			# Field 2: Command: DSITickle(5)
			# Manually queue the DSITickle message.
			$$shared{'conn_sem'}->down();
			syswrite($conn, pack('CCnNNN', 0, OP_DSI_TICKLE,
					$$shared{'requestid'}++ % 65536, 0, 0, 0));
			$$shared{'conn_sem'}->up();
			$last_tickle = $now;
		}
	}
	$$shared{'running'} = -1;
	undef $$shared{'conn_fd'};
	close($conn);

	# Return kFPNoServer to any still-waiting callers. (Sort of a hack to
	# deal with netatalk shutting down the connection right away when FPLogout
	# is received, instead of waiting for the client to send DSICloseSession.
	# Thanks again, netatalk. :| )
	foreach my $id (keys %{$$shared{'handlers'}}) {
		$handler = $$shared{'handlers'}{$id};
			${$$handler[2]} = kFPNoServer;
			${$$handler[0]}->up();
	}
} # }}}1

=head1 CONSTRUCTOR

=over

=item new (CLASS, HOST[, PORT])

Create a new DSI session object which will connect to the indicated host,
and (optionally) the indicated port. If no port is specified, the default
TCP port will be used for the connection. The host may be an IPv4 or
IPv6 (if L<IO::Socket::INET6> is present) address, or a DNS name.

=cut
sub new { # {{{1
	my ($class, $host, $port) = @_;
	$port ||= 548;
	my $obj = bless {}, $class;

	my $shared = &share({});
	%$shared = (
				 # 0 means starting, 1 means running, -1 means stopped
				 'running'		=> 0,
				 # set to 1 to stop the main loop
				 'exit'			=> 0,
				 # a counter for a (mostly) unique sequence ID for messages
				 # sent to the server.
				 'requestid'	=> 0,
				 'conn_fd'		=> undef,
				 'conn_sem'		=> new Thread::Semaphore(0),
				 # completion handlers are registered here.
				 'handlers'		=> &share({}),
				 # server attention messages queued here, should have
				 # Net::AFP::TCP check these
				 'attnq'		=> &share([]),
			   );

	$$obj{'Shared'} = $shared;
	my $thread = threads->create(\&session_thread, $shared, $host, $port);
	$$obj{'Dispatcher'} = $thread;
	$$shared{'conn_sem'}->down();
	$$obj{'Conn'} = new IO::Handle;
	if ($$shared{'running'} == 1) {
		$$obj{'Conn'}->fdopen($$shared{'conn_fd'}, 'w');
		$$obj{'Conn'}->autoflush(1);
	}
	$$shared{'conn_sem'}->up();

	return $obj;
} # }}}1
=back

=head2 METHODS

=over

=item close

=cut
sub close { # {{{1
	my ($self) = @_;
	$$self{'Shared'}{'exit'} = 1;
	$$self{'Dispatcher'}->join();
} # }}}1

=item SendMessage (CMD, MESSAGE, DATA_R, D_LEN, SEM_R, RC_R, RESP_R)
# Arguments:
#	$self:		A Net::DSI instance.
#	$cmd:		The numeric opcode of the command we wish to issue to the DSI
#		 		server.
#	$message:	The message payload, if any, to send with the command. Many
#				of the command opcodes don't take any payload.
#	$data_r:	Reference to additional data outside the payload to include
#				in the sent message; only used for DSIWrite operation.
#	$sem_r:		A reference to contain a Thread::Semaphore object which can
#				be used to determine when a response has been received. If
#				no response is expected, should be undef.
#	$resp_r:	A reference to a scalar, which will be made shared and will
#				receive the response when one is received. If no response is
#				expected, this should be undef.
#	$rc_r:		A reference to a scalar,
=cut
sub SendMessage { # {{{1
	my ($self, $cmd, $message, $data_r, $d_len, $sem_r, $resp_r, $rc_r) = @_;

	if (defined $sem_r) {
		# Create the Thread::Semaphore object, and initialize it to 0;
		# the first down() (which will be called by whoever called us) will
		# block until up() occurs.
		$sem_r = &share($sem_r);
		$$sem_r = new Thread::Semaphore(0);
	}

	$resp_r ||= *foo{SCALAR};
	$resp_r = &share($resp_r);

	$rc_r ||= *bar{SCALAR};
	$rc_r = &share($rc_r);

	$message ||= '';

	$data_r ||= \'';
	$d_len ||= length($$data_r);

	# Cycle the request ID that DSI uses to identify the request/reply
	# pairing. I'd like to handle that part asynchronously eventually.
	my $reqId = $$self{'Shared'}{'requestid'}++ % 65536;

	if ($$self{'Shared'}{'running'} == -1) {
		$$sem_r->up() if defined $sem_r;
		return kFPNoServer;
	}
	# Assemble the message header to be sent to the AFP over TCP server.
	# Arg 1: byte  Flags: 0 for request, 1 for reply
	# Arg 2: byte  Command
	# Arg 3: short RequestID
	# Arg 4: long  ErrCode: should be 0 for requests, should contain the
	# 		data offset for DSIWrite messages
	# Arg 5: long  MsgLength
	# Arg 6: long  Reserved: 0
	my $msg = pack('CCnNNNa*', 0, $cmd, $reqId,
			$d_len > 0 ? length($message) : 0,
			length($message) + $d_len, 0, $message);

	if (defined $sem_r) {
		my $handler = &share([]);
		@$handler = ( $sem_r, $resp_r, $rc_r );
		$$self{'Shared'}{'handlers'}{$reqId} = $handler;
	}

	# Send the request packet to the server.
	$$self{'Shared'}{'conn_sem'}->down();
	syswrite($$self{'Conn'}, $msg);
	if ($d_len) {
		syswrite($$self{'Conn'}, $$data_r, $d_len);
	}
	$$self{'Shared'}{'conn_sem'}->up();

	return $reqId;
} # }}}1

=item DSICloseSession

=cut
sub DSICloseSession { # {{{1
	my ($self) = @_;

	# Issue the DSICloseSession command to the server. Apparently the
	# server doesn't have anything to say in response.
	my $reqId = $self->SendMessage(OP_DSI_CLOSESESSION);
	return undef;
} # }}}1

=item DSICommand

=cut
sub DSICommand { # {{{1
	my ($self, $message, $resp_r) = @_;

	# Require that the caller includes a reference to stuff a reply block
	# into - issuing a DSICommand generally gets one.
	my $sem;
	my $rc;
	my $reqId = $self->SendMessage(OP_DSI_COMMAND, $message, undef, undef,
			\$sem, $resp_r, \$rc);
	$sem->down();
	return $reqId if $reqId < 0;

	return $rc;
} # }}}1

=item DSIGetStatus

=cut
sub DSIGetStatus { # {{{1
	my ($self, $resp_r) = @_;

	# Require that the caller provide a ref to stuff the reply block into.
	# This command is always going to provide a reply block, and the
	# information it contains is kind of important.
	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
	my $sem;
	my $rc;
	my $reqId = $self->SendMessage(OP_DSI_GETSTATUS, undef, undef, undef,
			\$sem, $resp_r, \$rc);
	$sem->down();
	return $reqId if $reqId < 0;

	return $rc;
} # }}}1

=item DSIOpenSession

=cut
sub DSIOpenSession { # {{{1
	my ($self, %options) = @_;

	my $options_packed = '';
	foreach my $key (keys %options) {
		my $opttype;
		my $optdata;
		if ($key eq 'RequestQuanta') {
			$opttype = kRequestQuanta;
			$optdata = pack('N', $options{$key});
		} elsif ($key eq 'AttentionQuanta') {
			$opttype = kAttentionQuanta;
			$optdata = pack('N', $options{$key});
		} elsif ($key eq 'ServerReplayCacheSize') {
			$opttype = kServerReplayCacheSize;
			$optdata = pack('N', $options{$key});
		} else {
			die('Unknown option key ' . $key);
		}
		$options_packed .=  pack('CC/a*', $opttype, $optdata);
	}

	my $sem;
	my $rc;
	my $resp;
	my $reqId = $self->SendMessage(OP_DSI_OPENSESSION, $options_packed, undef,
			undef, \$sem, \$resp, \$rc);
	return $reqId if $reqId < 0;
	$sem->down();
	
	my %rcvd_opts;
	while (length($resp) > 0) {
		my ($opttype, $optdata) = unpack('CC/a', $resp);
		if ($opttype == kRequestQuanta) {
			$rcvd_opts{'RequestQuanta'} = unpack('N', $optdata);
		} elsif ($opttype == kAttentionQuanta) {
			$rcvd_opts{'AttentionQuanta'} = unpack('N', $optdata);
		} elsif ($opttype == kServerReplayCacheSize) {
			$rcvd_opts{'ServerReplayCacheSize'} = unpack('N', $optdata);
		}
		$resp = substr($resp, 2 + length($optdata));
	}
	return wantarray ? ($rc, %rcvd_opts) : $rc;
} # }}}1

# This issues a keep-alive message to the server. This really needs to be
# done on a regular basis - hence why I want to have a separate thread to
# do dispatch duty, so it can handle things like that.
=item DSITickle

=cut
sub DSITickle { # {{{1
	my ($self) = @_;

	my $reqId = $self->SendMessage(OP_DSI_TICKLE);
} # }}}1

=item DSIWrite

=cut
sub DSIWrite { # {{{1
	# This should only be used for FPWrite and FPAddIcon
	my ($self, $message, $data_r, $d_len, $resp_r) = @_;

	my $sem;
	my $rc;
	my $reqId = $self->SendMessage(OP_DSI_WRITE, $message, $data_r, $d_len, \$sem,
			$resp_r, \$rc);
	return $reqId if $reqId < 0;
	$sem->down();
	return $rc;
} # }}}1

=back

=head1 REFERENCES

The Data Stream Interface protocol implementation contained herein is based
on the protocol description as provided by Apple, in the "AppleShare IP
6.3 Developer's Kit". The document is available freely via the Internet
in PDF form, at:

L<http://developer.apple.com/documentation/macos8/pdf/ASAppleTalkFiling2.1_2.2.pdf>

=cut
1;
# vim: ts=4 fdm=marker
