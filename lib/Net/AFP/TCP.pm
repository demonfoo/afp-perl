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
# only do 'require', the 'import' part will be done during _our_ 'import'.
require Net::DSI;
use Exporter;
use Log::Log4perl;

our @EXPORT = qw($kFPShortName $kFPLongName $kFPUTF8Name $kFPSoftCreate
                 $kFPHardCreate $kFPStartEndFlag $kFPLockUnlockFlag);
use base qw(Exporter Net::AFP);

##no critic qw(RequireFinalReturn RequireArgUnpacking)
sub import {
    Net::DSI->import(@_);
    Net::AFP::TCP->export_to_level(1);
}

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
    $obj->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    $obj->{Session} = Net::DSI->new($host, $port);
    # We need to be pushing at least the first option, and if the server
    # speaks AFP 3.3 or later, we should ask for a replay cache, because
    # apparently it's up to us?
    my($rc, %opts) = $obj->{Session}->OpenSession(
        RequestQuanta         => 1048576,
        ServerReplayCacheSize => 128,
    );
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

##no critic qw(ProhibitBuiltInHomonyms ProhibitAmbiguousNames)
sub close { # {{{1
    my ($self) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    $self->{Session}->CloseSession();
    $self->{Session}->close();
    return;
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPMessage { # {{{1
    my ($self, $payload, $resp_r, $can_cache) = @_;
    $self->{logger}->debug(sub { sprintf 'called %s()', (caller 3)[3] });

    $self->CheckAttnQueue();
    if ($can_cache && exists $self->{ReplayCache}) {
        do {
            shift @{$self->{ReplayCache}};
        ##no critic qw(ProhibitPostfixControls)
        } while (scalar(@{$self->{ReplayCache}}) > $self->{ReplayCacheSize});
        push @{$self->{ReplayCache}}, $payload;
    }
    return $self->{Session}->Command($payload, $resp_r);
} # }}}1

# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
##no critic qw(ProhibitManyArgs)
sub SendAFPWrite { # {{{1
    my ($self, $payload, $data_r, $d_len, $resp_r, $from_fh) = @_;
    $self->{logger}->debug(sub { sprintf 'called %s()', (caller 3)[3] });

    $self->CheckAttnQueue();
    return $self->{Session}->Write($payload, $data_r, $d_len, $resp_r, $from_fh);
} # }}}1

sub GetStatus { # {{{1
    my ($class, $host, $port, $resp_r) = @_;
    if (ref $class) {
        croak('GetStatus() should NEVER be called against an active object');
    }
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf 'called %s()', (caller 3)[3] });

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
