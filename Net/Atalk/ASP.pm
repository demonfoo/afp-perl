# This is Net::Atalk::ASP. It implements (mostly correctly) the ASP
# (AppleTalk Session Protocol) layer of the AppleTalk protocol family.
# It has a programming interface similar to Net::DSI; DSI was designed
# to layer over TCP/IP in a similar request/response fashion to ASP.
package Net::Atalk::ASP;

use Net::Atalk::ATP;
use Net::Atalk;			# for pack_sockaddr_at, unpack_sockaddr_at, atalk_aton
use threads::shared;	# for share
use strict;
use warnings;

use constant kASPNoError		=> 0;
use constant kASPBadVersNum		=> -1066;
use constant kASPBufTooSmall	=> -1067;
use constant kASPNoMoreSessions	=> -1068;
use constant kASPNoServers		=> -1069;
use constant kASPParamErr		=> -1070;
use constant kASPServerBusy		=> -1071;
use constant kASPSessClosed		=> -1072;
use constant kASPSizeErr		=> -1073;
use constant kASPTooManyClients	=> -1074;
use constant kASPNoAck			=> -1075;

=head1 NAME

Net::Atalk::ASP - Object interface for AppleTalk Session Protocol

=head1 SYNOPSIS

    use Net::Atalk::ASP;

=head1 DESCRIPTION

C<Net::Atalk::ASP> provides an object-based interface to interacting with
AppleTalk Session Protocol-based services, specifically AFP. It builds on
the L<Net::Atalk::ATP> interface to implement the command semantics.

=cut

use constant SP_VERSION				=> 0x0100;

use constant OP_SP_CLOSESESS		=> 1;
use constant OP_SP_COMMAND			=> 2;
use constant OP_SP_GETSTATUS		=> 3;
use constant OP_SP_OPENSESS			=> 4;
use constant OP_SP_TICKLE			=> 5;
use constant OP_SP_WRITE			=> 6;
use constant OP_SP_WRITECONTINUE	=> 7;
use constant OP_SP_ATTENTION		=> 8;

use constant SP_TIMEOUT				=> 120;

=head1 CONSTRUCTOR

=over

=item new (HOST, PORT)

Creates a C<Net::Atalk::ASP> object. Requires an AppleTalk host address
and DDP port number.

=cut
sub new { # {{{1
	my ($class, $host, $port) = @_;

	my $obj = bless {}, $class;
	$$obj{'atpsess'} = new Net::Atalk::ATP();
	return undef unless defined $$obj{'atpsess'};
	$$obj{'host'} = $host;
	$$obj{'svcport'} = $port;
	$$obj{'last_tickle'} = undef;

	return $obj;
} # }}}1
=back

=cut
sub _TickleFilter { # {{{1
	my ($realport, $lt_ref, $RqCB) = @_;
	my ($txtype) = unpack('C', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_TICKLE && $portno == $realport) {
		$$lt_ref = time();
		return [];
	}
	return undef;
} # }}}1

sub _TickleCheck {
	my ($lt_ref, $time, $shared) = @_;

	if ($$lt_ref + SP_TIMEOUT < $time) {
		print "no tickle in more than timeout period, setting exit flag\n";
		$$shared{'exit'} = 1;
	}
}

sub _AttnFilter { # {{{1
	my ($sid, $attnq_r, $realport, $RqCB) = @_;
	my ($txtype, $sessid, $attncode) = unpack('CCn', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_ATTENTION && $sessid == $sid && $realport == $portno) {
		push(@$attnq_r, $attncode);
		return [ { 'userbytes' => pack('x[4]'), 'data' => ''} ];
	}
	return undef;
} # }}}1

sub _CloseFilter { # {{{1
	my ($sid, $shared, $realport, $RqCB) = @_;
	my ($txtype, $sessid) = unpack('CCx[2]', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_CLOSESESS && $sessid == $sid && $realport == $portno) {
		$$shared{'exit'} = 1;
		return [ { 'userbytes' => pack('x[4]'), 'data' => ''} ];
	}
	return undef;
} # }}}1

=head2 METHODS

=over

=item close ()

Discontinue an active ASP session.

=cut
sub close { # {{{1
	my ($self) = @_;

	$$self{'atpsess'}->close();
} # }}}1

# Apparently this just returns these fixed values always...
=item SPGetParms (RESP_R)

The C<SPGetParms> call retrieves the maximum values of the command block
size and the quantum size.

RESP_R must be a scalar ref which will contain a hash ref with the size
bound information. The hash will contain the following:

=over

=item MaxCmdSize

The maximum size of a command block.

=item QuantumSize

The maximum size for a command reply or a write.

=back

=cut
sub SPGetParms { # {{{1
	my ($self, $resp_r) = @_;

	$$resp_r = {
				 'MaxCmdSize'	=> ATP_MAXLEN,
				 'QuantumSize'	=> ATP_MAXLEN * 8,
			   };

	return kASPNoError;
} # }}}1

=item SPGetStatus (RESP_R)

The C<SPGetStatus> call is used by a workstation ASP client to obtain
status information for a particular server.

RESP_R must be a scalar ref which will contain a hash ref with the
parsed structure data from the SPGetStatus call.

=cut
sub SPGetStatus { # {{{1
	my ($self, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	my ($rdata, $success);
	my $msg = pack('Cx[3]', OP_SP_GETSTATUS);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $msg,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 3,
		'PeerAddr'			=> $sa,
	);
	return $sem unless ref($sem);
	$sem->down();
	unless ($success) { return kASPNoServers; }
	$$resp_r = $$rdata[0][1];
	return kASPNoError;
} # }}}1

=item SPOpenSession

The C<SPOpenSession> call is issued by an ASP client after obtaining the
internet address of the SLS (server listening socket) through an NBPLookup
call. If a session is successfully opened, then a session reference
number is returned and stored in the session object, to be used for
all subsequent calls in this session. If a session cannot be opened,
an appropriate SPError value is returned.

=cut
sub SPOpenSession { # {{{1
	my ($self) = @_;

	my $wss = $$self{'atpsess'}->sockport();;
	my $msg = pack('CCn', OP_SP_OPENSESS, $wss, SP_VERSION);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $msg,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 3,
		'PeerAddr'			=> $sa,
		'ExactlyOnce'		=> ATP_TREL_30SEC,
	);
	return $sem unless ref($sem);
	$sem->down();
	unless ($success) { return kASPNoServers; }
	my ($srv_sockno, $sessionid, $errno) = unpack('CCn', $$rdata[0][0]);
	@$self{'sessport', 'sessionid'} = ($srv_sockno, $sessionid);
	$$self{'seqno'} = 0;
	$errno = ($errno & 0x8000) ? -((~$errno & 0xFFFF) + 1) : $errno;
	if ($errno == kASPNoError) { # {{{2
		# This will cause the client code to send an SPTickle, and resend
		# it every 30 seconds, forever. The server never actually sends
		# back a "response" to the pending transaction, thus forcing the
		# tickle request to keep going automatically, with no extra additions
		# required to the thread.
		$self->SPTickle(30, -1);

		# Handle incoming Attention requests.
		$$self{'attnq'} = &share([]);
		my $filter = &share([]);
		@$filter = ( __PACKAGE__ . '::_AttnFilter', $$self{'sessionid'},
				$$self{'attnq'}, $$self{'sessport'} );
		$$self{'atpsess'}->AddTransactionFilter($filter);
		# Handle CloseSession requests from the server.
		$filter = &share([]);
		@$filter = ( __PACKAGE__ . '::_CloseFilter', $$self{'sessionid'},
				$$self{'atpsess'}{'Shared'}, $$self{'sessport'});
		$$self{'atpsess'}->AddTransactionFilter($filter);

		my $lt_ref = \$$self{'last_tickle'};
		share($lt_ref);
		$$lt_ref = time();

		$filter = &share([]);
		# We have to pass the fully qualified subroutine name because we can't
		# pass subroutine refs from thread to thread.
		@$filter = ( __PACKAGE__ . '::_TickleFilter', $$self{'sessport'},
				$lt_ref );
		$$self{'atpsess'}->AddTransactionFilter($filter);
		my $cb = &share([]);
		@$cb = ( __PACKAGE__ . '::_TickleCheck', $lt_ref );
		$$self{'atpsess'}->AddPeriodicCallback(5, $cb);
	} # }}}2
	return $errno;
} # }}}1

=item SPCloseSession

The C<SPCloseSession> call can be issued at any time by the ASP client to
close a session previously opened through an C<SPOpenSession> call. As a
result of the call, the session reference number is invalidated and
cannot be used for any further calls. In addition, all pending activity
on the session is immediately canceled.

=cut
sub SPCloseSession { # {{{1
	my ($self) = @_;

	my $msg = pack('CCx[2]', OP_SP_CLOSESESS, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $msg,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 1,
		'NumTries'			=> 1,
		'PeerAddr'			=> $sa,
	);
	delete $$self{'sessionid'};
	return kASPNoError;
} # }}}1

=item SPCommand (MESSAGE, RESP_R)

Once a session has been opened, the workstation end client can send a
command to the server end by issuing an C<SPCommand> call to ASP. A
command block of maximum size (L<MaxCmdSize>) can be send with the
command. If the length of MESSAGE is greater than the maximum allowable
size, the call returns an error of kASPSizeErr; in this case, no effort
is made to send anything to the server end.

MESSAGE contains the binary data for the outgoing request. RESP_R must
be a scalar ref that will contain the reassembled response data, if any,
received from the server in response to the request sent.

=cut
sub SPCommand { # {{{1
	my ($self, $message, $resp_r) = @_;

	$resp_r = defined($resp_r) ? $resp_r : *foo{SCALAR};

	my $seqno = $$self{'seqno'}++ % (2 ** 16);
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be processed as part of the request.
	my $ub = pack('CCn', OP_SP_COMMAND, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $ub,
		'Data'				=> $message,
		'ResponseLength'	=> 8,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 5,
		'PeerAddr'			=> $sa,
		'ExactlyOnce'		=> ATP_TREL_30SEC
	);
	return $sem unless ref($sem);
	$sem->down();
	unless ($success) { return kASPNoServers; }
	# string the response bodies back together
	$$resp_r = join('', map { $$_[1]; } @$rdata);
	# user bytes from the first response packet are the only ones that
	# are relevant...
	my ($errno) = unpack('N', $$rdata[0][0]);
	$errno = ($errno & 0x80000000) ? -((~$errno & 0xFFFFFFFF) + 1) : $errno;
	return $errno;
} # }}}1

=item SPWrite (MESSAGE, DATA_R, D_LEN, RESP_R)

The C<SPWrite> call is made by the ASP client in order to write a block
of data to the server end of the session. The call first delivers the
command block (no larger than L<MaxCmdSize>) to the server end client
of the ASP session and, as previously described, the server end can
then transfer the write data or return an error (delivered in the
result code field).

Thee actual amount of data sent will be less than or equal to the
length of the data chunk provided and will never be larger than
L<QuantumSize>. The amount of write data actually transferred is
returned in the response block.

In response to an C<SPWrite>, the server end returns two quantities:
a 4-byte command result code and a variable-length command reply
that is returned in the reply buffer. Note that this reply can be
no larger than L<QuantumSize>.

MESSAGE contains the binary data for the outgoing request. DATA_R must
be a scalar ref to the binary data to be written to the server. RESP_R
must be a scalar ref that will contain the reassembled response data
received from the server in response to the request sent.

=cut
sub SPWrite { # {{{1
	my ($self, $message, $data_r, $d_len, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
	die('$data_r must be a scalar ref')
			unless ref($data_r) eq 'SCALAR' or ref($data_r) eq 'REF';
	$d_len ||= length($$data_r);

	my $seqno = $$self{'seqno'}++ % (2 ** 16);
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be processed as part of the request.
	my $ub = pack('CCn', OP_SP_WRITE, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $ub,
		'Data'				=> $message,
		'ResponseLength'	=> 8,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 5,
		'PeerAddr'			=> $sa,
		'ExactlyOnce'		=> ATP_TREL_30SEC
	);
	return $sem unless ref($sem);

	# Try getting an SPWriteContinue transaction request from the server
	my $RqCB = $$self{'atpsess'}->GetTransaction(1, sub {
		my ($txtype, $sessid, $pseq) = unpack('CCn', $_[0]{'userbytes'});
		my ($portno, $paddr) = unpack_sockaddr_at($_[0]{'sockaddr'});

		return($txtype == OP_SP_WRITECONTINUE &&
				$sessid == $$self{'sessionid'} && $seqno == $pseq &&
				$portno == $$self{'sessport'});
	} );
	my $bufsize = unpack('n', $$RqCB{'data'});

	my $resp = &share([]);

	my $sendsize = 0;
	my $totalsend = 0;
	for (my $i = 0; $i < 8; $i++) { # {{{2
		last if $totalsend >= $d_len;
		$sendsize = ATP_MAXLEN;
		if ($bufsize - $totalsend < ATP_MAXLEN) {
			$sendsize = $bufsize - $totalsend;
		}
		if ($d_len - $totalsend < $sendsize) {
			$sendsize = $d_len - $totalsend;
		}
		my $elem = &share({});
		%$elem = ( 'userbytes'	=> pack('x[4]'),
				   'data'		=> substr($$data_r, $totalsend, $sendsize) );
		push(@$resp, $elem);
		$totalsend += $sendsize;
	} # }}}2

	$$self{'atpsess'}->RespondTransaction($RqCB, $resp);

	$sem->down();
	# string the response bodies back together
	$$resp_r = join('', map { $$_[1]; } @$rdata);
	# user bytes from the first response packet are the only ones that
	# are relevant...
	my ($errno) = unpack('N', $$rdata[0][0]);
	$errno = ($errno & 0x80000000) ? -((~$errno & 0xFFFFFFFF) + 1) : $errno;

	return $errno;
} # }}}1

# This call only needs to be used internally; there should be no reason
# for an ASP client to call this directly.
sub SPTickle { # {{{1
	my ($self, $interval, $ntries) = @_;

	my $msg = pack('CCx[2]', OP_SP_TICKLE, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $msg,
		'ResponseLength'	=> 1,
		'Timeout'			=> $interval,
		'NumTries'			=> $ntries,
		'PeerAddr'			=> $sa,
	);
} # }}}1

=back

=head1 REFERENCES

The AppleTalk Session Protocol implementation contained herein is based
on the protocol description as provided by Apple, in the book "Inside
AppleTalk", chapter 11. "Inside AppleTalk" is available freely via the
Internet in PDF form, at:

L<http://developer.apple.com/MacOs/opentransport/docs/dev/Inside_AppleTalk.pdf>

=head1 SEE ALSO

C<Net::Atalk::ATP>

=head1 AUTHOR

Derrik Pates <demon@devrandom.net>

=cut
1;
# vim: ts=4 fdm=marker
