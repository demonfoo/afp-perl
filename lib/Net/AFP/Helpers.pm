package Net::AFP::Helpers;

use strict;
use warnings;
use diagnostics;
use Carp;
use Errno qw(:POSIX);
use English qw(-no_match_vars);

# We need at least Perl 5.8 to make this all go...
use 5.010;

use Exporter;

use base qw(Exporter);
our @EXPORT = qw(do_afp_connect);

require Net::AFP::TCP;
use Net::AFP::Result;
use Net::AFP::Versions;
use Net::AFP::UAMs;
use Socket;
use URI::Escape;

##no critic qw(RequireFinalReturn RequireArgUnpacking)
sub import {
    Net::AFP::TCP->import(@_);
    Net::AFP::Helpers->export_to_level(1);
}

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
                  \z}xsm;

sub do_afp_connect {
    my($pw_cb, $url, $srvInfo_r, %options) = @_;

    # Establish the preferred address family selection order.
    my @af_order = (AF_INET6, AF_INET);
    if ($has_atalk) {
        push @af_order, AF_APPLETALK;
    }

    if (exists $options{aforder}) {
        if (ref($options{aforder}) ne q{ARRAY}) {
            croak(q{Invalid 'aforder' passed, please correct});
        }
        @af_order = @{$options{aforder}};
    }

    if (not($url =~ $url_rx)) {
        printf {\*STDERR} qq{URL '%s' was not valid, sorry\n}, $url;
        exit EINVAL();
    }
    my %values = %LAST_PAREN_MATCH;

    foreach (keys %values) {
        $values{$_} = uri_unescape($values{$_});
    }

    if (not defined $values{host}) {
        ##no critic qw(RequireCheckedSyscalls)
        print {\*STDERR} qq{Could not extract host from AFP URL\n};
        exit EINVAL();
    }

    my($srvInfo, $rc, $host, $port);
    if ($values{atalk_transport}) {
        if (not $has_atalk) {
            croak q{AppleTalk support libraries not available};
        }

        my @records = NBPLookup($values{host}, q{AFPServer}, $values{port},
                undef, 1);
        if (not scalar @records) {
            croak(q{Could not resolve NBP name } . $values{host} .
		      q{:AFPServer@} . ($values{port} ? $values{port} : q{*}));
        }
        ($host, $port) = @{$records[0]}[0,1];

        $rc = Net::AFP::Atalk->GetStatus($host, $port, \$srvInfo);
    }
    else {
        $rc = Net::AFP::TCP->GetStatus(@values{qw[host port]}, \$srvInfo);
    }
    if ($rc != $kFPNoErr) {
        printf {\*STDERR} qq{Could not issue GetStatus on %s\n}, $values{host};
        return ENODEV();
    }

    if (ref($srvInfo_r) eq q{SCALAR}) {
        ${$srvInfo_r} = $srvInfo;
    }

    # Should probably handle the 'NetworkAddresses' item being nonexistant or
    # empty. Prior to AFP 2.2, that data didn't even exist. Of course, prior
    # to AFP 2.2, there was no TCP socket support, so that kind of simplifies
    # matters.
    if (!exists(${$srvInfo}{NetworkAddresses}) ||
            !scalar(@{${$srvInfo}{NetworkAddresses}})) {
        if ($values{atalk_transport}) {
            ${$srvInfo}{NetworkAddresses} = [ {
                family  => AF_APPLETALK(),
                address => $host,
                port    => $port,
            } ];
        }
        else {
            croak(q{Server supplied no NetworkAddresses, but using IP transport; server is broken});
        }
    }

    my $session;
    my $using_atalk = 0;
TRY_AFS:
    foreach my $af (@af_order) {
        my @sa_list;
        foreach (@{${$srvInfo}{NetworkAddresses}}) {
            if (not exists $_->{family}) {
                next;
            }
            if ($_->{family} == $af) {
                push @sa_list, $_;
            }
        }

TRY_SOCKADDRS:
        foreach my $sa (@sa_list) {
            if ($af == AF_APPLETALK) {
                if (not $has_atalk) {
                    carp(q{AF_APPLETALK endpoint selected, but atalk support not available});
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

            last TRY_AFS if ref $session and $session->isa(q{Net::AFP});
        }
    }

    if (not ref $session or not $session->isa(q{Net::AFP})) {
        ##no critic qw(RequireCheckedSyscalls)
        print {\*STDERR} q{Failed connecting to all endpoints supplied } .
          qq{by server?\n};
        return ENODEV();
    }

    my $cv = Net::AFP::Versions::GetPreferredVersion(${$srvInfo}{AFPVersions},
            $using_atalk);
    if (not $cv) {
        ##no critic qw(RequireCheckedSyscalls)
        print {\*STDERR} q{Couldn't agree on an AFP protocol version with } .
                qq{the server\n};
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
            printf {\*STDERR} qq{Error occurred during login: %s\n}, afp_strerror($rv);
            $session->close();
            return EACCES();
        }
    }
    else {
        my $rv = Net::AFP::UAMs::GuestAuth($session, $cv);
        if ($rv != $kFPNoErr) {
            printf {\*STDERR} qq{Error occurred during login: %s\n}, afp_strerror($rv);
            $session->close();
            return EACCES();
        }
    }

    if (wantarray) {
        return($session, %values);
    }
    else {
        return $session;
    }
}

1;
