# This is Net::Atalk::ASP. It will eventually implement the ASP (AppleTalk
# Session Protocol) layer of the AppleTalk protocol family. It should have
# a programming interface similar to Net::DSI; DSI was designed to layer
# over TCP/IP in a similar request/response fashion to ASP.
package Net::Atalk::ASP;

use Net::Atalk::ATP;
use Net::Atalk;
use IO::Poll qw(POLLRDNORM POLLWRNORM POLLIN POLLHUP);
use IO::Handle;
use Net::AFP::Result;
use threads;
use threads::shared;
use Thread::Semaphore;
use Exporter qw(import);
use strict;
use warnings;

$::__ASP_DEBUG = 1;

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
	return $obj;
}

sub close {
	my ($self) = @_;

	$$self{'atpsess'}->close();
}

# FIXME: Gotta figure out how to implement this...
sub SPGetParms {
	my ($self, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
}

sub SPGetStatus {
	my ($self, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
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

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
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
	return $errno;
}

sub SPCloseSession {
	my ($self) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	my $msg = pack('CCx[2]', OP_SP_CLOSESESS, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(0, $sa, '', $msg,
			1, \$rdata, 2, 3, 0, \$success);
	$sem->down();
	unless ($success) { return SPNoServers; }
	# No actual data is returned, just a packet with 4 zero'd UserBytes.
	delete $$self{'sessionid'};
	return SPNoError;
}

sub SPCommand {
	my ($self, $message, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;

	$resp_r = defined($resp_r) ? $resp_r : *foo{SCALAR};

	my $seqno = $$self{'seqno'}++;
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be 
	my $ub = pack('CCn', OP_SP_COMMAND, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(1, $sa, $message,
			$ub, 8, \$rdata, 2, 3, ATP_TREL_30SEC, \$success);
	$sem->down();
	unless ($success) { return SPNoServers; }
	print '', (caller(0))[3], ": response contains ", scalar(@$rdata), " response packets, assembling\n";
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

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	my $seqno = $$self{'seqno'}++;
	# this will take an ATP_MSGLEN sized chunk of the message data and
	# send it to the server, to be 
	my $ub = pack('CCn', OP_SP_WRITE, $$self{'sessionid'}, $seqno);
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	print '', (caller(0))[3], ": Sending SPWrite transaction to server\n";
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(1, $sa, $message,
			$ub, 8, \$rdata, 2, 3, ATP_TREL_30SEC, \$success);
	print '', (caller(0))[3], ": Blocking on sem to wait for completion\n";
	$sem->down();
	print '', (caller(0))[3], ": Transaction completed\n";
	unless ($success) { return SPNoServers; }
	#print '', (caller(0))[3], ": response contains ", scalar(@$rdata), " response packets, assembling\n";
	# string the response bodies back together
	$$resp_r = join('', map { $$_[1]; } @$rdata);
	# user bytes from the first response packet are the only ones that
	# are relevant...
	my ($errno) = unpack('N', $$rdata[0][0]);
	$errno = ($errno & 0x80000000) ? -((~$errno & 0xFFFFFFFF) + 1) : $errno;

	my $count = 0;
	do {
		# Try getting an SPWriteContinue transaction request from the server
		print '', (caller(0))[3], ": Waiting for an SPWriteContinue transaction from server\n";
		my $RqCB = $$self{'atpsess'}->GetTransaction(1, sub {
			my ($txtype, $sessid, $pseq) = unpack('CCn', $_[0]{'userbytes'});
			return($txtype == OP_SP_WRITECONTINUE && $sessid == $$self{'sessionid'} && $seqno == $pseq);
		} );
		my $bufsize = unpack('n', $$RqCB{'payload'});
		print '', (caller(0))[3], ": Server buffer size is ", $bufsize, "\n";

		my @resp;

		my $sendsize = 0;
		my $totalsend = 0;
		for (my $i = 0; $i < 8; $i++) {
			$sendsize = ATP_MAXLEN;
			if ($bufsize - $totalsend < ATP_MAXLEN) {
				$sendsize = $bufsize - $totalsend;
			}
			push(@resp, { 'userbytes'	=> pack('x[4]'),
						  'payload'		=> substr($$data_r, $count + $totalsend, $sendsize) } );
			$totalsend += $sendsize;
		}
		$count += $totalsend;

		print '', (caller(0))[3], ": Sending WriteContinue transaction response\n";
		$$self{'atpsess'}->RespondTransaction($$RqCB{'txid'}, \@resp);
	} while (length($$data_r) > $count);
	return $errno;
}

sub SPTickle {
	my ($self, $interval, $ntries) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	my $msg = pack('CCx[2]', OP_SP_TICKLE, $$self{'sessionid'});
	my $sa = pack_sockaddr_at($$self{'sessport'} , atalk_aton($$self{'host'}));
	my ($rdata, $success);
	my ($txid, $sem) = $$self{'atpsess'}->SendTransaction(0, $sa, '', $msg,
			1, \$rdata, $interval, $ntries, 0, \$success);
	print '', (caller(0))[3], ": Transaction ID is ", $txid, "\n";
}

1;
# vim: ts=4 fdm=marker
