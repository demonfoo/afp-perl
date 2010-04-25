# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over AppleTalk protocol.
package Net::AFP::Atalk;
use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::Atalk::ASP;
use Exporter;

use strict;
use warnings;

our @ISA = qw(Net::AFP);
our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
				 kFPHardCreate);

sub new {
	my ($class, $host, $port) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $obj = {};
	bless $obj, $class;

	$$obj{'ASPSession'} = new Net::Atalk::ASP($host, $port);
	my $rc = $$obj{'ASPSession'}->SPOpenSession();
	# This will cause the client code to send an SPTickle, and resend
	# it every 30 seconds, forever. The server never actually sends
	# back a "response" to the pending transaction, thus forcing the
	# tickle request to keep going automatically, with no extra additions
	# required to the thread.
	$$obj{'ASPSession'}->SPTickle(30, -1);
	return $rc unless $rc == SPNoError;
	return $obj;
}


sub close {
	my ($self) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

	$$self{'ASPSession'}->SPCloseSession();
	$$self{'ASPSession'}->close();
}

sub CheckAttnQueue {
	my ($self) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $RqCB = $$self{'ASPSession'}{'atpsess'}->GetTransaction(0, sub {
		my ($txtype, $sessid) = unpack('CC', $_[0]{'userbytes'});
		return($txtype == 8 && $sessid == $$self{'ASPSession'}{'sessionid'}); # OP_SP_ATTENTION
	} );
	return unless defined $RqCB;
	my ($attncode) = unpack('x[2]n', $$RqCB{'userbytes'});
	$$self{'ASPSession'}{'atpsess'}->RespondTransaction($$RqCB{'txid'}, [ { userbytes => pack('x[4]'), payload => '' } ]);
	print '', (caller(0))[3], ": AttnCode is $attncode\n";
}

sub SendAFPMessage {
	my ($self, $payload, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	$self->CheckAttnQueue();
	return $$self{'ASPSession'}->SPCommand($payload, $resp_r);
}

sub SendAFPWrite { # {{{1
	my ($self, $payload, $data_r, $resp_r) = @_;
	
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	$self->CheckAttnQueue();
	return $$self{'ASPSession'}->SPWrite($payload, $data_r, $resp_r);
} # }}}1

sub GetStatus { # {{{1
	my ($class, $host, $port, $resp_r) = @_;
	if (ref($class)) {
		die('GetStatus() should NEVER be called against an active object');
		return -1;
	}

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $obj = new Net::Atalk::ASP($host, $port);
	my $resp;
	my $rc = $obj->SPGetStatus(\$resp);
	$obj->close();
	return $rc unless $rc == SPNoError;

	$$resp_r = _ParseSrvrInfo($resp);
	return $rc;
} # }}}1

1;
# vim: ts=4 ai fdm=marker
