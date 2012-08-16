# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over AppleTalk protocol.
package Net::AFP::Atalk;
use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::Atalk::ASP;
use Exporter qw(import);
use Log::Log4perl qw(:easy);

use strict;
use warnings;

our @ISA = qw(Net::AFP);
our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
                 kFPHardCreate kFPStartEndFlag kFPLockUnlockFlag);

# Arguments:
#	$class: The class (Net::AFP::Atalk) to create an instance of. This
#			must be invoked as 'new Net::AFP::Atalk' or
#			'Net::AFP::Atalk->new'.
#	$host: The AppleTalk address of the server to connect to.
#	$port: The port to connect to. The host address and port should
#		   be obtained using NBPLookup() in Net::Atalk::NBP.
sub new { # {{{1
	my ($class, $host, $port) = @_;
	DEBUG('called ', (caller(0))[3]);
    my $obj = $class->SUPER::new($host, $port);

	$$obj{'Session'} = new Net::Atalk::ASP($host, $port);
	my $rc = $$obj{'Session'}->SPOpenSession();
    if ($rc != kFPNoErr) {
        $$obj{'Session'}->close();
        return $rc;
    }
	return $obj;
} # }}}1

sub close { # {{{1
	my ($self) = @_;
	DEBUG('called ', (caller(0))[3]);

	$$self{'Session'}->SPCloseSession();
	$$self{'Session'}->close();
} # }}}1

sub CheckAttnQueue { # {{{1
	my ($self) = @_;

	DEBUG('called ', (caller(0))[3]);
	my $attnq = $$self{'Session'}{'attnq'};
	my $vol_update_checked;
	while (my $msg = shift(@$attnq)) {
		if ($msg & 0x8000) {	# server says it's shutting down
			INFO("CheckAttnQueue(): Received notification of server intent to shut down");
			INFO("Shutdown in ", ($msg & 0xFFF), " minutes");
			if ($msg & 0x2000) { # server also has a message for us
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					INFO("Shut down message: \"", $$MsgData{'ServerMessage'}, "\"");
				}
			}
		}
		elsif ($msg & 0x4000) { # server says it's crashing
			INFO("CheckAttnQueue(): Received notification server is crashing; should really attempt reconnection, I suppose...");
		}
		elsif ($msg & 0x2000) { # server message?
			if ($msg & 0x1000) { # server notification
				if ($msg & 0x1) {
					next if $vol_update_checked;
					INFO("CheckAttnQueue(): ModDate updated on an attached volume, should do FPGetVolParms() to recheck");
					$vol_update_checked = 1;
				}
			}
			else { # server message
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					INFO("Server message: \"", $$MsgData{'ServerMessage'}, "\"");
				}
			}
		}
	}
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPMessage { # {{{1
	my ($self, $payload, $resp_r) = @_;

	DEBUG('called ', (caller(0))[3]);
	$self->CheckAttnQueue();
	return $$self{'Session'}->SPCommand($payload, $resp_r);
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPWrite { # {{{1
	my ($self, $payload, $data_r, $d_len, $resp_r) = @_;
	
	DEBUG('called ', (caller(0))[3]);
	$self->CheckAttnQueue();
	return $$self{'Session'}->SPWrite($payload, $data_r, $d_len, $resp_r);
} # }}}1

sub GetStatus { # {{{1
	my ($class, $host, $port, $resp_r) = @_;
	if (ref($class)) {
		die('GetStatus() should NEVER be called against an active object');
		return -1;
	}

	DEBUG('called ', (caller(0))[3]);
	my $obj = new Net::Atalk::ASP($host, $port);
	my $resp;
	my $rc = $obj->SPGetStatus(\$resp);
	$obj->close();
	return $rc unless $rc == kFPNoErr;

	$$resp_r = _ParseSrvrInfo($resp);
	return $rc;
} # }}}1

1;
# vim: ts=4 ai fdm=marker
