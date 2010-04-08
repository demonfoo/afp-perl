# This is Net::DSI::Session. It is an implementation of the DSI shim
# protocol that acts as a mid-layer between AFP and TCP protocols. This
# implementation is fairly complete; it doesn't properly handle server
# notifications, but otherwise it handles pretty much everything worth
# caring about.
package Net::DSI::Session;

my $has_IO_Socket_INET6 = 1;
eval { require IO::Socket::INET6; };
if ($@) {
	$has_IO_Socket_INET6 = 0;
}
use IO::Socket::INET;
use IO::Poll qw(POLLRDNORM POLLWRNORM POLLIN POLLHUP);
use IO::Handle;
use Net::AFP::Result;
use Time::HiRes qw(gettimeofday);
use threads;
use threads::shared;
use Thread::Semaphore;
use strict;
use warnings;
use Data::Dumper;

use constant OP_DSI_CLOSESESSION	=> 1;
use constant OP_DSI_COMMAND			=> 2;
use constant OP_DSI_GETSTATUS		=> 3;
use constant OP_DSI_OPENSESSION		=> 4;
use constant OP_DSI_TICKLE			=> 5;
use constant OP_DSI_WRITE			=> 6;
use constant OP_DSI_ATTENTION		=> 8;

use constant kRequestQuanta			=> 0x00;
# not sure if this is the canonical name for this option code...
use constant kAttentionQuanta		=> 0x01;
use constant kServerReplayCacheSize	=> 0x02;

# This function is the body of our thread. It's a dispatcher arrangement, and
# it will also send periodic (~30 second interval) keepalive messages to the
# server side. $shared will contain a shared data structure with an incoming
# request queue (from the caller to the server), with data being returned to
# the client through a reference, and completion notification handled via a
# Thread::Semaphore object.. It also contains a 'running' flag, to allow
# potential callers to know if the thread is in play or not.
sub session_thread { # {{{1
	my($shared, $host, $port) = @_;

	# Set up the connection to the server. Then we need to check that we've
	# connected successfully.
	my $conn = undef;
	my %connect_args = ( 'PeerAddr'		=> $host,
						 'PeerPort'		=> $port,
						 'HostPort'		=> 0,
						 'Proto'		=> 'tcp',
						 'Type'			=> SOCK_STREAM,
						 'MultiHomed'	=> 1 );
	if ($has_IO_Socket_INET6 == 1) {
		# Try using IO::Socket::INET6 once first, before trying with
		# IO::Socket::INET; on Linux INET6 can be used for both, but on
		# *BSD, it can't.
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

	$$shared{'conn_fd'} = fileno($conn);
	$$shared{'conn_sem'}->up();
	$$shared{'running'} = 1;
	$$shared{'sockaddr'} = $conn->sockaddr();
	$$shared{'sockport'} = $conn->sockport();
	$$shared{'peeraddr'} = $conn->peeraddr();
	$$shared{'peerport'} = $conn->peerport();
	$$shared{'sockdomain'} = AF_INET;
	if (ref($conn) eq 'IO::Socket::INET6') {
		$$shared{'sockdomain'} = $conn->sockdomain();
	}

	# Get the FD number for use with select(), and assign a few other
	# important values. Also preallocate several variables which will be
	# used in the main loop.
	my $poll = new IO::Poll;
	$poll->mask($conn, POLLRDNORM);
	my($data, $real_length, $resp);
	my($type, $cmd, $id, $errcode, $length, $reserved);
	while ($$shared{'exit'} == 0) {
		if ($poll->poll(30) > 0) {
			# Try to get a message from the server.
#			$resp = '';
			my $rsz = sysread($conn, $resp, 16);
			last unless defined $rsz;
			next unless $rsz == 16;
			($type, $cmd, $id, $errcode, $length, $reserved) =
					unpack('CCnNNN', $resp);
	
#			$data = '';
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

				# FIXME: probably should handle OP_DSI_ATTENTION here.
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

		# send a DSITickle to the server
		# Field 2: Command: DSITickle(5)
		# Manually queue the DSITickle message.
		$$shared{'conn_sem'}->down();
		syswrite($conn, pack('CCnNNN', 0, OP_DSI_TICKLE,
				$$shared{'requestid'}++ % 65536, 0, 0, 0));
		$$shared{'conn_sem'}->up();
	}
	$$shared{'running'} = -1;
	undef $$shared{'Conn'};
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

# Arguments:
#	$class: The class we're being called against. This class has to be
#			instantiated like 'new Net::DSI::Session' or
#			'Net::DSI::Session->new' because of this.
#	$host: Currently an IP address (a DNS name should work too, though)
#		   indicating the DSI server (AFP over TCP server) that we wish
#		   to attach to.
sub new { # {{{1
	my ($class, $host, $port) = @_;
	unless (defined $port) {
		$port = 548;
	}
	my $obj = {};
	bless $obj, $class;

	my $shared = &share({});
	%$shared = (
				 # 0 means starting, 1 means running, -1 means stopped
				 'running'		=> 0,
				 # set to 1 to stop the main loop
				 'exit'			=> 0,
				 # a counter for a (mostly) unique sequence ID for messages
				 # sent to the server.
				 'requestid'	=> 0,
				 # requests to be dispatched go here.
				 #'sendq'		=> &share([]),
				 'conn_fd'		=> undef,
				 'conn_sem'		=> new Thread::Semaphore(0),
				 # completion handlers are registered here.
				 'handlers'		=> &share({}),
			   );

	$$obj{'Shared'} = $shared;
	my $thread = threads->create(\&session_thread, $shared, $host, $port);
	$$obj{'Dispatcher'} = $thread;
	$$shared{'conn_sem'}->down();
	$$obj{'Conn'} = new IO::Handle;
	$$obj{'Conn'}->fdopen($$shared{'conn_fd'}, 'w');
	$$shared{'conn_sem'}->up();

	return $obj;
} # }}}1

# Need to implement this.
sub close { # {{{1
	my ($self) = @_;
	$$self{'Shared'}{'exit'} = 1;
	$$self{'Dispatcher'}->join();
} # }}}1

# Arguments:
#	$self:		A Net::DSI::Session instance.
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
sub SendMessage { # {{{1
	my ($self, $cmd, $message, $data_r, $sem_r, $resp_r, $rc_r) = @_;

	if (defined $sem_r) {
		# Create the Thread::Semaphore object, and initialize it to 0;
		# the first down() (which will be called by whoever called us) will
		# block until up() occurs.
		$sem_r = &share($sem_r);
		$$sem_r = new Thread::Semaphore(0);
	}

	$resp_r = defined($resp_r) ? $resp_r : \'';
	$resp_r = &share($resp_r);

	$rc_r = defined($rc_r) ? $rc_r : \'';
	$rc_r = &share($rc_r);

	$message = defined($message) ? $message : '';

	$data_r = defined($data_r) ? $data_r : \'';

	# Cycle the request ID that DSI uses to identify the request/reply
	# pairing. I'd like to handle that part asynchronously eventually.
	my $reqId = $$self{'Shared'}{'requestid'}++ % 65536;

	if ($$self{'Shared'}{'running'} == -1) {
		return kFPNoServer;
	}
	# Assemble the message header to be sent to the AFP over TCP server.
	# Arg 1: byte Flags: 0 for request, 1 for reply
	# Arg 2: byte Command
	# Arg 3: short RequestID
	# Arg 4: long ErrCode: should be 0 for requests, should contain the
	# 		data offset for DSIWrite messages
	# Arg 5: long MsgLength
	# Arg 6: long Reserved: 0
	my $dlen = length($$data_r);
	my $msg = pack('CCnNNNa*', 0, $cmd, $reqId,
			$dlen > 0 ? length($message) : 0,
			length($message) + $dlen, 0, $message);

	if (defined $sem_r) {
		my $handler = &share([]);
		@$handler = ( $sem_r, $resp_r, $rc_r );
		$$self{'Shared'}{'handlers'}{$reqId} = $handler;
	}

	# Don't send the message until after the handler has been set. Otherwise
	# we open ourselves up to a race condition which can cause the whole mess
	# to block forever. :|
	# Okay, let's try direct dispatch instead of queuing...
	$$self{'Shared'}{'conn_sem'}->down();
	syswrite($$self{'Conn'}, $msg);
	if (length($$data_r)) {
		syswrite($$self{'Conn'}, $$data_r);
	}
	$$self{'Shared'}{'conn_sem'}->up();

	return $reqId;
} # }}}1

sub DSICloseSession { # {{{1
	my ($self) = @_;

	# Issue the DSICloseSession command to the server. Apparently the
	# server doesn't have anything to say in response.
	my $reqId = $self->SendMessage(OP_DSI_CLOSESESSION);
	return undef;
} # }}}1

sub DSICommand { # {{{1
	my ($self, $message, $resp_r) = @_;

	# Require that the caller includes a reference to stuff a reply block
	# into - issuing a DSICommand generally gets one.
	my $sem = undef;
	my $rc = undef;
	my $reqId = $self->SendMessage(OP_DSI_COMMAND, $message, undef, \$sem,
			$resp_r, \$rc);
	return $reqId if $reqId < 0;
	$sem->down();

	return $rc;
} # }}}1

sub DSIGetStatus { # {{{1
	my ($class, $host, $port, $resp_r) = @_;
	if (ref($class) ne '') {
		warn("DSIGetStatus() should NEVER be called against an open DSI context");
		return -1;
	}

	# Require that the caller provide a ref to stuff the reply block into.
	# This command is always going to provide a reply block, and the
	# information it contains is kind of important.
	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
	my $obj = $class->new($host, $port);
	return ($obj) unless ref($obj) ne '' and $obj->isa('Net::DSI::Session');
	my $sem = undef;
	my $rc = undef;
	my $reqId = $obj->SendMessage(OP_DSI_GETSTATUS, undef, undef, \$sem,
			$resp_r, \$rc);
	return $reqId if $reqId < 0;
	$sem->down();
	$obj->close();

	return $rc;
} # }}}1

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

	my $sem = undef;
	my $rc = undef;
	my $resp = undef;
	my $reqId = $self->SendMessage(OP_DSI_OPENSESSION, $options_packed, undef,
			\$sem, \$resp, \$rc);
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
sub DSITickle { # {{{1
	my ($self) = @_;

	my $reqId = $self->SendMessage(OP_DSI_TICKLE);
} # }}}1

sub DSIWrite { # {{{1
	# This should only be used for FPWrite and FPAddIcon
	my ($self, $message, $data_r, $resp_r) = @_;

	my $sem = undef;
	my $rc = undef;
	my $reqId = $self->SendMessage(OP_DSI_WRITE, $message, $data_r, \$sem,
			$resp_r, \$rc);
	return $reqId if $reqId < 0;
	$sem->down();
	return $rc;
} # }}}1

1;
# vim: ts=4 fdm=marker
