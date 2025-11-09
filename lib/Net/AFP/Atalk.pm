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
    my ($self, $payload, $data_r, $d_len, $resp_r, $from_fh) = @_;
    #$self->{logger}->debug(sub { sprintf 'called %s()', (caller(3))[3] });

    $self->CheckAttnQueue();
    # sendfile() isn't an option for AppleTalk based sockets anyway, so
    # the best thing to do is just to do the read ourselves if needed and
    # pass that on...
    if (defined $from_fh) {
        $data_r = *quux{SCALAR};
        ${$data_r} = q{};
        sysread $from_fh, ${$data_r}, $d_len;
    }
    return $self->{Session}->Write($payload, $data_r, $d_len, $resp_r);
} # }}}1

sub GetStatus { # {{{1
    my ($class, $host, $port, $resp_r) = @_;
    if (ref $class) {
        croak(q{GetStatus() should NEVER be called against an active object});
    }
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

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
# vim: ts=4 ai fdm=marker et sw=4
