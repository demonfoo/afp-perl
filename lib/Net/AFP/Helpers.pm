package Net::AFP::Helpers;

use strict;
use warnings;
use diagnostics;
use Carp;
use Errno qw(:POSIX);

# We need at least Perl 5.8 to make this all go...
use v5.8;

use Exporter qw(import);

our @EXPORT = qw(do_afp_connect);

use Net::AFP::TCP;
use Net::AFP::Result;
use Net::AFP::Versions;
use Net::AFP::UAMs;
use Socket;
use URI::Escape;

my $has_atalk = 0;
eval {
    require Net::AFP::Atalk;    # The class to connect to an AppleTalk server
                                # via AppleTalk protocol.
    require Net::Atalk::NBP;
    1;
} and do {
    $has_atalk = 1;
    Net::Atalk::NBP->import;
};

# Set up the pattern to use for breaking the AFP URL into its components.
our $url_rx;
if ($] >= 5.010) {
    $url_rx = qr{^
                  (afps?):/             # protocol specific prefix
                  (at)?/                # optionally specify atalk transport
                  (?:                   # authentication info block
                      ([^:\@/;]*)       # capture username
                      (?:;AUTH=([^:\@/;]+))? # capture uam name
                      (?::([^:\@/;]*))? # capture password
                  \@)?                  # closure of auth info capture
                  (?|([^:/\[\]:]+)|\[([^\]]+)\]) # capture target host
                  (?::([^:/;]+))?       # capture optional port
                  (?:/(?:               # start path capture
                      ([^:/;]+)         # first path element is vol name
                      (/.*)?            # rest of path is local subpath
                  )?)?                  # closure of path capture
                  $}xs;
}
elsif ($] >= 5.008) {
    # Since we can't do (?|...) in Perl 5.8.x (didn't get added till 5.10),
    # just leave it out in this version.
    $url_rx = qr{^
                  (afps?):/             # protocol specific prefix
                  (at)?/                # optionally specify atalk transport
                  (?:                   # authentication info block
                      ([^:\@/;]*)       # capture username
                      (?:;AUTH=([^:\@/;]+))? # capture uam name
                      (?::([^:\@/;]*))? # capture password
                  \@)?                  # closure of auth info capture
                  ([^:/\[\]:]+)         # capture target host
                  (?::([^:/;]+))?       # capture optional port
                  (?:/(?:               # start path capture
                      ([^:/;]+)         # first path element is vol name
                      (/.*)?            # rest of path is local subpath
                  )?)?                  # closure of path capture
                  $}xs;
}
our @args = qw(protocol atalk_transport username UAM password host port
               volume subpath);

sub do_afp_connect {
    my($pw_cb, $url, $srvInfo_r, %options) = @_;

    # Establish the preferred address family selection order.
    my @af_order = (AF_INET6, AF_INET);
    if ($has_atalk) {
        push(@af_order, AF_APPLETALK);
    }

    if (exists $options{'aforder'}) {
        unless (ref($options{'aforder'}) eq 'ARRAY') {
            croak('Invalid \'aforder\' passed, please correct');
        }
        @af_order = @{$options{'aforder'}};
    }

    my %values;
    unless (@values{@args} = $url =~ $url_rx) {
        print STDERR "URL ", $url, " was not valid, sorry\n";
        exit(&EINVAL);
    }

    foreach (keys(%values)) {
        $values{$_} = uri_unescape($values{$_});
    }

    unless (defined $values{'host'}) {
        print STDERR "Could not extract host from AFP URL\n";
        exit(&EINVAL);
    }

    my($srvInfo, $rc, $host, $port);
    if ($values{'atalk_transport'}) {
        croak "AppleTalk support libraries not available"
                unless $has_atalk;

        my @records = NBPLookup($values{'host'}, 'AFPServer', $values{'port'},
                undef, 1);
        croak("Could not resolve NBP name " . $values{'host'})
                unless scalar(@records);
        ($host, $port) = @{$records[0]}[0,1];

        $rc = Net::AFP::Atalk->GetStatus($host, $port, \$srvInfo);
    }
    else {
        $rc = Net::AFP::TCP->GetStatus(@values{'host', 'port'}, \$srvInfo);
    }
    if ($rc != kFPNoErr) {
        print STDERR "Could not issue GetStatus on ", $values{'host'}, "\n";
        return &ENODEV;
    }

    if (ref($srvInfo_r) eq 'SCALAR') {
        $$srvInfo_r = $srvInfo;
    }

    # Should probably handle the 'NetworkAddresses' item being nonexistant or
    # empty. Prior to AFP 2.2, that data didn't even exist. Of course, prior
    # to AFP 2.2, there was no TCP socket support, so that kind of simplifies
    # matters.
    if (!exists($srvInfo->{'NetworkAddresses'}) ||
            !scalar(@{$srvInfo->{'NetworkAddresses'}})) {
        if ($values{'atalk_transport'}) {
            $srvInfo->{'NetworkAddresses'} = [ {
                'family'    => AF_APPLETALK,
                'address'   => $host,
                'port'      => $port,
            } ];
        }
        else {
            # This is a crappy workaround for Jaffer being stupid.
            $srvInfo->{'NetworkAddresses'} = [ {
                'family'    => AF_INET,
                'address'   => $values{'host'},
                'port'      => $values{'port'},
            } ];
        }
    }

    my $session;
    my $using_atalk = 0;
TRY_AFS:
    foreach my $af (@af_order) {
        my @sa_list;
        foreach (@{$srvInfo->{'NetworkAddresses'}}) {
            next unless exists $_->{'family'};
            if ($_->{'family'} == $af) {
                push(@sa_list, $_)
            }
        }

TRY_SOCKADDRS:
        foreach my $sa (@sa_list) {
            if ($af == AF_APPLETALK) {
                unless ($has_atalk) {
                    carp('AF_APPLETALK endpoint selected, but atalk support not available');
                    next TRY_SOCKADDRS;
                }
                $session = new Net::AFP::Atalk($sa->{'address'}, $sa->{'port'});
                $using_atalk = 1;
            }
            else {
                $session = new Net::AFP::TCP($sa->{'address'},
						$sa->{'port'} || 548);
                $using_atalk = 0;
            }

            last TRY_AFS if ref($session) and $session->isa('Net::AFP');
        }
    }

    unless (ref($session) and $session->isa('Net::AFP')) {
        print STDERR "Failed connecting to all endpoints supplied by server?\n";
        return &ENODEV;
    }

    my $cv = Net::AFP::Versions::GetPreferredVersion($$srvInfo{'AFPVersions'},
            $using_atalk);
    unless ($cv) {
        print STDERR "Couldn't agree on an AFP protocol version with the " .
                "server\n";
        $session->close();
        return &ENODEV;
    }

    if (defined $values{'username'}) {
        my $uamlist = $$srvInfo{'UAMs'};
        if ($values{'UAM'}) {
            $uamlist = [ $values{'UAM'} ];
        }
        my $rc = Net::AFP::UAMs::PasswordAuth($session, $cv, $uamlist,
                $values{'username'}, sub {
                    return &$pw_cb(%values)
                });
        unless ($rc == kFPNoErr) {
            print STDERR "Incorrect username/password while trying to authenticate\n";
            $session->close();
            return &EACCES;
        }
    }
    else {
        my $rc = Net::AFP::UAMs::GuestAuth($session, $cv);
        unless ($rc == kFPNoErr) {
            print STDERR "Anonymous authentication failed\n";
            $session->close();
            return &EACCES;
        }
    }

    if (wantarray()) {
        return($session, %values);
    }
    else {
        return $session;
    }
}
