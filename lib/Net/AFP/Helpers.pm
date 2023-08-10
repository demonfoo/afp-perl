package Net::AFP::Helpers;

use strict;
use warnings;
use diagnostics;
use Carp;
use Errno qw(:POSIX);
use English qw(-no_match_vars);

# We need at least Perl 5.8 to make this all go...
use 5.010;

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
my $url_rx = qr{\A
                  (?<protocol>afps?):/          # protocol specific prefix
                  (?<atalk_transport>at)?/      # optionally specify atalk transport
                  (?:                           # authentication info block
                      (?<username>[^:\@/;]*)    # capture username
                      (?:;AUTH=(?<UAM>[^:\@/;]+))? # capture uam name
                      (?::(?<password>[^:\@/;]*))? # capture password
                  \@)?                          # closure of auth info capture
                  (?|(?<host>[^:/\[\]:]+)|\[(?<host>[^\]]+)\]) # capture target host
                  (?::(?<port>[^:/;]+))?        # capture optional port
                  (?:/(?:                       # start path capture
                      (?<volume>[^:/;]+)        # first path element is vol name
                      (?<subpath>/.*)?          # rest of path is local subpath
                  )?)?                          # closure of path capture
                  \z}xs;

sub do_afp_connect {
    my($pw_cb, $url, $srvInfo_r, %options) = @_;

    # Establish the preferred address family selection order.
    my @af_order = (AF_INET6, AF_INET);
    if ($has_atalk) {
        push(@af_order, AF_APPLETALK);
    }

    if (exists $options{aforder}) {
        if (ref($options{aforder}) ne 'ARRAY') {
            croak(q{Invalid 'aforder' passed, please correct});
        }
        @af_order = @{$options{aforder}};
    }

    if (not($url =~ $url_rx)) {
        print STDERR "URL '", $url, "' was not valid, sorry\n";
        exit(EINVAL());
    }
    my %values = %LAST_PAREN_MATCH;

    foreach (keys(%values)) {
        $values{$_} = uri_unescape($values{$_});
    }

    if (not defined $values{host}) {
        print STDERR "Could not extract host from AFP URL\n";
        exit(EINVAL());
    }

    my($srvInfo, $rc, $host, $port);
    if ($values{atalk_transport}) {
        croak "AppleTalk support libraries not available"
                unless $has_atalk;

        my @records = NBPLookup($values{host}, q{AFPServer}, $values{port},
                undef, 1);
        croak('Could not resolve NBP name ' . $values{host} .
		q{:AFPServer@} . ($values{port} ? $values{port} : q{*}))
                unless scalar(@records);
        ($host, $port) = @{$records[0]}[0,1];

        $rc = Net::AFP::Atalk->GetStatus($host, $port, \$srvInfo);
    }
    else {
        $rc = Net::AFP::TCP->GetStatus(@values{qw[host port]}, \$srvInfo);
    }
    if ($rc != $kFPNoErr) {
        print STDERR "Could not issue GetStatus on ", $values{host}, "\n";
        return ENODEV();
    }

    if (ref($srvInfo_r) eq 'SCALAR') {
        ${$srvInfo_r} = $srvInfo;
    }

    # Should probably handle the 'NetworkAddresses' item being nonexistant or
    # empty. Prior to AFP 2.2, that data didn't even exist. Of course, prior
    # to AFP 2.2, there was no TCP socket support, so that kind of simplifies
    # matters.
    if (!exists($srvInfo->{NetworkAddresses}) ||
            !scalar(@{$srvInfo->{NetworkAddresses}})) {
        if ($values{atalk_transport}) {
            $srvInfo->{NetworkAddresses} = [ {
                family  => AF_APPLETALK(),
                address => $host,
                port    => $port,
            } ];
        }
        else {
            croak("Server supplied no NetworkAddresses, but using IP transport; server is broken");
        }
    }

    my $session;
    my $using_atalk = 0;
TRY_AFS:
    foreach my $af (@af_order) {
        my @sa_list;
        foreach (@{$srvInfo->{NetworkAddresses}}) {
            next unless exists $_->{family};
            if ($_->{family} == $af) {
                push(@sa_list, $_)
            }
        }

TRY_SOCKADDRS:
        foreach my $sa (@sa_list) {
            if ($af == AF_APPLETALK) {
                if (not $has_atalk) {
                    carp('AF_APPLETALK endpoint selected, but atalk support not available');
                    next TRY_SOCKADDRS;
                }
                $session = Net::AFP::Atalk->new($sa->{address}, $sa->{port});
                $using_atalk = 1;
            }
            else {
                $session = Net::AFP::TCP->new($sa->{address},
						$sa->{port} || 548);
                $using_atalk = 0;
            }

            last TRY_AFS if ref($session) and $session->isa('Net::AFP');
        }
    }

    if (not(ref($session) and $session->isa('Net::AFP'))) {
        print STDERR "Failed connecting to all endpoints supplied by server?\n";
        return ENODEV();
    }

    my $cv = Net::AFP::Versions::GetPreferredVersion($srvInfo->{AFPVersions},
            $using_atalk);
    if (not $cv) {
        print STDERR "Couldn't agree on an AFP protocol version with the " .
                "server\n";
        $session->close();
        return ENODEV();
    }

    if (defined $values{username}) {
        my $uamlist = ${$srvInfo}{UAMs};
        if ($values{UAM}) {
            $uamlist = [ $values{UAM} ];
        }
        my $rv = Net::AFP::UAMs::PasswordAuth($session, $cv, $uamlist,
                $values{username}, sub {
                    return &{$pw_cb}(%values)
                });
        if ($rv != $kFPNoErr) {
            print STDERR "Incorrect username/password while trying to authenticate\n";
            $session->close();
            return EACCES();
        }
    }
    else {
        my $rv = Net::AFP::UAMs::GuestAuth($session, $cv);
        if ($rv != $kFPNoErr) {
            print STDERR "Anonymous authentication failed\n";
            $session->close();
            return EACCES();
        }
    }

    if (wantarray()) {
        return($session, %values);
    }
    else {
        return $session;
    }
}

1;
