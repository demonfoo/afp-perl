# This is Net::Atalk::ASP. It will eventually implement the ASP (AppleTalk
# Session Protocol) layer of the AppleTalk protocol family. It should have
# a programming interface similar to Net::DSI; DSI was designed to layer
# over TCP/IP in a similar request/response fashion to ASP.
package Net::Atalk::ASP;

use Net::Atalk::ATP;
use Net::Atalk;
use IO::Poll qw(POLLRDNORM POLLWRNORM POLLIN POLLHUP);
use Net::AFP::Result;
use threads;
use threads::shared;
use Exporter qw(import);
use strict;
use warnings;

use constant SP_VERSION				=> 0x0100;

use constant OP_SP_CLOSESESS		=> 1;
use constant OP_SP_COMMAND			=> 2;
use constant OP_SP_GETSTATUS		=> 3;
use constant OP_SP_OPENSESS			=> 4;
use constant OP_SP_TICKLE			=> 5;
use constant OP_SP_WRITE			=> 6;
use constant OP_SP_WRITECONTINUE	=> 7;
use constant OP_SP_ATTENTION		=> 8;

use constant SPNoError				=> 0;
use constant SPBadVersNum			=> -1066;
use constant SPBufTooSmall			=> -1067;
use constant SPNoMoreSessions		=> -1068;
use constant SPNoServers			=> -1069;
use constant SPParamErr				=> -1070;
use constant SPServerBusy			=> -1071;
use constant SPSessClosed			=> -1072;
use constant SPSizeErr				=> -1073;
use constant SPTooManyClients		=> -1074;
use constant SPNoAck				=> -1075;

our @EXPORT = qw(SPNoError SPBadVersNum SPBufTooSmall SPNoMoreSessions
		SPNoServers SPParamErr SPServerBusy SPSessClosed SPSizeErr
		SPTooManyClients SPNoAck);

sub new {
	my ($class, $host, $port) = @_;

	my $obj = bless {}, $class;
	$$obj{'atpsess'} = new Net::Atalk::ATP();
	$$obj{'host'} = $host;
	$$obj{'svcport'} = $port;

	my $filter = &share([]);
	# We have to pass the fully qualified subroutine name because we can't
	# pass subroutine refs from thread to thread.
	@$filter = ( __PACKAGE__ . '::_TickleFilter', $port );
	$$obj{'atpsess'}->AddTransactionFilter($filter);

	return $obj;
}

sub _TickleFilter {
	my ($realport, $RqCB) = @_;
	my ($txtype) = unpack('C', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_TICKLE && $portno == $realport) { return [] }
	return undef;
}

sub _AttnFilter {
	my ($sid, $attnq_r, $realport, $RqCB) = @_;
	my ($txtype, $sessid, $attncode) = unpack('CCn', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_ATTENTION && $sessid == $sid && $realport == $portno) {
		push(@$attnq_r, $attncode);
		return [ { 'userbytes' => pack('x[4]'), 'payload' => ''} ];
	}
	return undef;
}

sub _CloseFilter {
	my ($sid, $shared, $realport, $RqCB) = @_;
	my ($txtype, $sessid) = unpack('CCx[2]', $$RqCB{'userbytes'});
	my ($portno, $paddr) = unpack_sockaddr_at($$RqCB{'sockaddr'});

	if ($txtype == OP_SP_CLOSESESS && $sessid == $sid && $realport == $portno) {
		$$shared{'exit'} = 1;
		return [ { 'userbytes' => pack('x[4]'), 'payload' => ''} ];
	}
	return undef;
}

sub close {
	my ($self) = @_;

	$$self{'atpsess'}->close();
}

# FIXME: Gotta figure out how to implement this...
sub SPGetParms {
	my ($self, $resp_r) = @_;

}

sub SPGetStatus {
	my ($self, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	my ($rdata, $success);
	my $msg = pack('Cx[3]', OP_SP_GETSTATUS);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(0, $sa, '', $msg, 1,
			\$rdata, 2, 3, 0, \$success);
	$sem->down();
	unless ($success) { return SPNoServers; }
	$$resp_r = $$rdata[0][1];
	return SPNoError;
}

sub SPOpenSession {
	my ($self) = @_;

	# FIXME: Should probably have a getter method for this...
	my $wss = $$self{'atpsess'}{'Shared'}{'sockport'};
	my $msg = pack('CCn', OP_SP_OPENSESS, $wss, SP_VERSION);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(1, $sa, '', $msg,
			1, \$rdata, 2, 3, ATP_TREL_30SEC, \$success);
	$sem->down();
	unless ($success) { return SPNoServers; }
	my ($srv_sockno, $sessionid, $errno) = unpack('CCn', $$rdata[0][0]);
	@$self{'sessport', 'sessionid'} = ($srv_sockno, $sessionid);
	$$self{'seqno'} = 0;
	$errno = ($errno & 0x8000) ? -((~$errno & 0xFFFF) + 1) : $errno;
	if ($errno == SPNoError) {
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
	}
	return $errno;
}

sub SPCloseSession {
	my ($self) = @_;

	my $msg = pack('CCx[2]', OP_SP_CLOSESESS, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(0, $sa, '', $msg,
			1, \$rdata, 1, 1, 0, \$success);
	delete $$self{'sessionid'};
	return SPNoError;
}

sub SPCommand {
	my ($self, $message, $resp_r) = @_;

	$resp_r = defined($resp_r) ? $resp_r : *foo{SCALAR};

	my $seqno = $$self{'seqno'}++ % 65536;
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be processed as part of the request.
	my $ub = pack('CCn', OP_SP_COMMAND, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(1, $sa, $message,
			$ub, 8, \$rdata, 5, -1, ATP_TREL_30SEC, \$success);
	$sem->down();
	unless ($success) { return SPNoServers; }
	# string the response bodies back together
	$$resp_r = join('', map { $$_[1]; } @$rdata);
	# user bytes from the first response packet are the only ones that
	# are relevant...
	my ($errno) = unpack('N', $$rdata[0][0]);
	$errno = ($errno & 0x80000000) ? -((~$errno & 0xFFFFFFFF) + 1) : $errno;
	return $errno;
}

sub SPWrite {
	my ($self, $message, $data_r, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	my $seqno = $$self{'seqno'}++ % 65536;
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be processed as part of the request.
	my $ub = pack('CCn', OP_SP_WRITE, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(1, $sa, $message,
			$ub, 8, \$rdata, 5, -1, ATP_TREL_30SEC, \$success);

	# Try getting an SPWriteContinue transaction request from the server
	my $RqCB = $$self{'atpsess'}->GetTransaction(1, sub {
		my ($txtype, $sessid, $pseq) = unpack('CCn', $_[0]{'userbytes'});
		my ($portno, $paddr) = unpack_sockaddr_at($_[0]{'sockaddr'});

		return($txtype == OP_SP_WRITECONTINUE &&
				$sessid == $$self{'sessionid'} && $seqno == $pseq &&
				$portno == $$self{'sessport'});
	} );
	my $bufsize = unpack('n', $$RqCB{'payload'});

	my $resp = &share([]);

	my $sendsize = 0;
	my $totalsend = 0;
	for (my $i = 0; $i < 8; $i++) {
		last if $totalsend > length($$data_r);
		$sendsize = ATP_MAXLEN;
		if ($bufsize - $totalsend < ATP_MAXLEN) {
			$sendsize = $bufsize - $totalsend;
		}
		my $elem = &share({});
		%$elem = ( 'userbytes'	=> pack('x[4]'),
				   'payload'	=> substr($$data_r, $totalsend, $sendsize) );
		push(@$resp, $elem);
		$totalsend += $sendsize;
	}

	$$self{'atpsess'}->RespondTransaction($$RqCB{'txid'}, $resp);

	$sem->down();
	# string the response bodies back together
	$$resp_r = join('', map { $$_[1]; } @$rdata);
	# user bytes from the first response packet are the only ones that
	# are relevant...
	my ($errno) = unpack('N', $$rdata[0][0]);
	$errno = ($errno & 0x80000000) ? -((~$errno & 0xFFFFFFFF) + 1) : $errno;

	return $errno;
}

sub SPTickle {
	my ($self, $interval, $ntries) = @_;

	my $msg = pack('CCx[2]', OP_SP_TICKLE, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(0, $sa, '', $msg,
			1, \$rdata, $interval, $ntries, 0, \$success);
}

1;
# vim: ts=4 fdm=marker
