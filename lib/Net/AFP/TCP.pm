# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over TCP protocol.
package Net::AFP::TCP;

use strict;
use warnings;
use diagnostics;
use integer;
use Carp;

use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::DSI;
use Exporter qw(import);
use Log::Log4perl;

use base qw(Net::AFP);
our @EXPORT = qw($kFPShortName $kFPLongName $kFPUTF8Name $kFPSoftCreate
                 $kFPHardCreate $kFPStartEndFlag $kFPLockUnlockFlag);

# Arguments:
#   $class: The class (Net::AFP::TCP) to create an instance of. This
#           must be invoked as 'new Net::AFP::TCP' or
#           'Net::AFP::TCP->new'.
#   $host: The IP address (a DNS name should work as well) of the AFP over
#          TCP server we wish to connect to. (IPv6 addresses will work as
#          well, if IO::Socket::IP is available.)
#   $port: The port to connect to. Should be 'undef' if the default port
#          is to be used (default is 548).
sub new { # {{{1
    my ($class, $host, $port, %params) = @_;
    my $obj = $class->SUPER::new($host, $port);
    $obj->{logger}->debug('called ', (caller 0)[3], '()');

    $obj->{Session} = Net::DSI->new($host, $port);
    my($rc, %opts) = $obj->{Session}->OpenSession();
    $obj->{RequestQuanta} = $opts{RequestQuanta};
    if (exists $opts{ServerReplayCacheSize}) {
        $obj->{ReplayCacheSize} = $opts{ServerReplayCacheSize};
        $obj->{ReplayCache} = [];
    }
    if ($rc != $kFPNoErr) {
        $obj->{Session}->close();
        return $rc;
    }
    return $obj;
} # }}}1

sub close { # {{{1
    my ($self) = @_;
    $self->{logger}->debug('called ', (caller 0)[3], '()');

    $self->{Session}->CloseSession();
    $self->{Session}->close();
    return;
} # }}}1

sub CheckAttnQueue { # {{{1
    my ($self) = @_;
    $self->{logger}->debug('called ', (caller 0)[3], '()');

    my $attnq = $self->{Session}{Shared}{attnq};
    my $vol_update_checked;
    while (my $msg = shift @{$attnq}) {
        if ($msg & 0x8_000) {    # server says it's shutting down
            $self->{logger}->info('CheckAttnQueue(): Received notification of server intent to shut down');
            $self->{logger}->info('Shutdown in ', ($msg & 0xFFF), ' minutes');
            if ($msg & 0x2_000) { # server also has a message for us
                my $MsgData;
                $self->FPGetSrvrMsg(1, 3, \$MsgData);
                if ($MsgData->{ServerMessage} ne q{}) {
                    $self->{logger}->info(q{Shut down message: "}, $MsgData->{ServerMessage}, q{"});
                }
            }
        }
        elsif ($msg & 0x4_000) { # server says it's crashing
            $self->{logger}->info(q{CheckAttnQueue(): Received notification } .
                q{server is crashing; should really attempt reconnection, I } .
                q{suppose...});
        }
        elsif ($msg & 0x2_000) { # server message?
            if ($msg & 0x1_000) { # server notification
                if ($msg & 0x1) {
                    next if $vol_update_checked;
                    $self->{logger}->info(q{CheckAttnQueue(): ModDate } .
                        q{updated on an attached volume, should do } .
                        q{FPGetVolParms() to recheck});
                    $vol_update_checked = 1;
                }
            }
            else { # server message
                my $MsgData;
                $self->FPGetSrvrMsg(1, 3, \$MsgData);
                if ($MsgData->{ServerMessage} ne q{}) {
                    $self->{logger}->info(q{Server message: "}, $MsgData->{ServerMessage}, q{"});
                }
            }
        }
    }
    return;
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPMessage { # {{{1
    my ($self, $payload, $resp_r, $can_cache) = @_;
    #$self->{logger}->debug('called ', (caller(0))[3], '()');

    $self->CheckAttnQueue();
    if ($can_cache && exists $self->{ReplayCache}) {
        do {
            shift @{$self->{ReplayCache}};
        } while ((scalar(@{$self->{ReplayCache}}) + 1) >=
                $self->{ReplayCacheSize});
        push @{$self->{ReplayCache}}, $payload;
    }
    return $self->{Session}->Command($payload, $resp_r);
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPWrite { # {{{1
    my ($self, $payload, $data_r, $d_len, $resp_r) = @_;
    #$self->{logger}->debug('called ', (caller(0))[3], '()');

    $self->CheckAttnQueue();
    return $self->{Session}->Write($payload, $data_r, $d_len, $resp_r);
} # }}}1

sub GetStatus { # {{{1
    my ($class, $host, $port, $resp_r) = @_;
    if (ref $class) {
        croak('GetStatus() should NEVER be called against an active object');
    }
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug('called ', (caller 0)[3], '()');

    my $obj = Net::DSI->new($host, $port);
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
