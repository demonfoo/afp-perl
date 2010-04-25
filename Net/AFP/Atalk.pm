# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over AppleTalk protocol.
package Net::AFP::Atalk;
use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::Atalk::ASP;
use threads::shared;
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
	return($rc == kFPNoErr ? $obj : $rc);
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
	my $attnq = $$self{'ASPSession'}{'attnq'};
	my $vol_update_checked;
	while (my $msg = shift(@$attnq)) {
		if ($msg & 0x8000) {	# server says it's shutting down
			print "CheckAttnQueue(): Received notification of server intent to shut down\n";
			print "Shutdown in ", ($msg & 0xFFF), " minutes\n";
			if ($msg & 0x2000) { # server also has a message for us
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					print "Shut down message: \"", $$MsgData{'ServerMessage'}, "\"\n";
				}
			}
		}
		elsif ($msg & 0x4000) { # server says it's crashing
			print "CheckAttnQueue(): Received notification server is crashing; should really attempt reconnection, I suppose...\n";
		}
		elsif ($msg & 0x2000) { # server message?
			if ($msg & 0x1000) { # server notification
				if ($msg & 0x1) {
					next if $vol_update_checked;
					print "CheckAttnQueue(): ModDate updated on an attached volume, should do FPGetVolParms() to recheck\n";
					$vol_update_checked = 1;
				}
			}
			else { # server message
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					print "Server message: \"", $$MsgData{'ServerMessage'}, "\"\n";
				}
			}
		}
	}
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
