# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over AppleTalk protocol.
package Net::AFP::Atalk;

use strict;
use warnings;
use diagnostics;
use integer;
use Carp;

use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::Atalk::ASP;
use Exporter qw(import);
use Log::Log4perl;

use base qw(Net::AFP);
our @EXPORT = qw($kFPShortName $kFPLongName $kFPUTF8Name $kFPSoftCreate
                 $kFPHardCreate $kFPStartEndFlag $kFPLockUnlockFlag);

# Arguments:
#   $class: The class (Net::AFP::Atalk) to create an instance of. This
#           must be invoked as 'new Net::AFP::Atalk' or
#           'Net::AFP::Atalk->new'.
#   $host: The AppleTalk address of the server to connect to.
#   $port: The port to connect to. The host address and port should
#          be obtained using NBPLookup() in Net::Atalk::NBP.
sub new { # {{{1
    my ($class, $host, $port) = @_;
    my $obj = $class->SUPER::new($host, $port);
    $obj->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    $obj->{Session} = Net::Atalk::ASP->new($host, $port);
    my $rc = $obj->{Session}->OpenSession();
    $obj->{Session}->GetParms(my $params);
    $obj->{RequestQuanta} = $params->{QuantumSize};
    if ($rc != $kFPNoErr) {
        $obj->{Session}->close();
        return $rc;
    }
    return $obj;
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms ProhibitAmbiguousNames)
sub close { # {{{1
    my ($self) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    $self->{Session}->CloseSession();
    $self->{Session}->close();
    return;
} # }}}1

sub CheckAttnQueue { # {{{1
    my ($self) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    my $attnq = $self->{Session}{Shared}{attnq};
    my $vol_update_checked;
    while (my $msg = shift @{$attnq}) {
        if ($msg & 0x8_000) {    # server says it's shutting down
            $self->{logger}->info(sub { sprintf q{%s(): Received notification } .
              q{of server intent to shut down}, (caller 3)[3] });
            $self->{logger}->info(sub { sprintf q{%s(): Shutdown in %d minutes},
              (caller 3)[3], ($msg & 0xFFF) });
            if ($msg & 0x2_000) { # server also has a message for us
                my $MsgData;
                $self->FPGetSrvrMsg(1, 3, \$MsgData);
                if ($MsgData->{ServerMessage} ne q{}) {
                    $self->{logger}->info(sub { sprintf q{%s(): Shut down } .
                      q{message: "%s"}, (caller 3)[3], $MsgData->{ServerMessage} });
                }
            }
        }
        elsif ($msg & 0x4_000) { # server says it's crashing
            $self->{logger}->info(sub { sprintf q{%s(): Received notification } .
                q{server is crashing; should really attempt reconnection, I } .
                q{suppose...}, (caller 3)[3] });
        }
        elsif ($msg & 0x2_000) { # server message?
            if ($msg & 0x1_000) { # server notification
                if ($msg & 0x1) {
                    next if $vol_update_checked;
                    $self->{logger}->info(sub { sprintf q{%s(): ModDate } .
                        q{updated on an attached volume, should do } .
                        q{FPGetVolParms() to recheck}, (caller 3)[3] });
                    $vol_update_checked = 1;
                }
            }
            else { # server message
                my $MsgData;
                $self->FPGetSrvrMsg(1, 3, \$MsgData);
                if ($MsgData->{ServerMessage} ne q{}) {
                    $self->{logger}->info(sub { sprintf q{%s(): Server message: "%s"},
                      (caller 3)[3], $MsgData->{ServerMessage} });
                }
            }
        }
    }
    return;
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPMessage { # {{{1
    my ($self, $payload, $resp_r) = @_;
    #$self->{logger}->debug(sub { sprintf 'called %s()', (caller(3))[3] });

    $self->CheckAttnQueue();
    return $self->{Session}->Command($payload, $resp_r);
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPWrite { # {{{1
    my ($self, $payload, $data_r, $d_len, $resp_r) = @_;
    #$self->{logger}->debug(sub { sprintf 'called %s()', (caller(3))[3] });

    $self->CheckAttnQueue();
    return $self->{Session}->Write($payload, $data_r, $d_len, $resp_r);
} # }}}1

sub GetStatus { # {{{1
    my ($class, $host, $port, $resp_r) = @_;
    if (ref $class) {
        croak('GetStatus() should NEVER be called against an active object');
    }
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf 'called %s()', (caller 3)[3] });

    my $obj = Net::Atalk::ASP->new($host, $port);
    my $resp;
    my $rc = $obj->GetStatus(\$resp);
    $obj->close();
    if ($rc != $kFPNoErr) {
        return $rc;
    }

    ${$resp_r} = ParseSrvrInfo($resp);
    return $rc;
} # }}}1

1;
# vim: ts=4 ai fdm=marker
