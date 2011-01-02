package Net::AFP::Helpers;

use strict;
use warnings;
use diagnostics;
use Carp;

# We need at least Perl 5.8 to make this all go...
use v5.8;

use Exporter qw(import);

our @EXPORT = qw(do_afp_connect);

use Net::AFP::TCP;
use Net::AFP::Result;
use Net::AFP::Versions;
use Net::AFP::UAMs;

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

my $has_IO__Socket__INET6 = 0;
eval {
    require IO::Socket::INET6;
    1;
} and do {
    $has_IO__Socket__INET6 = 1;
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
    my($pw_cb, $url) = @_;

    my %values;
    unless (@values{@args} = $url =~ $url_rx) {
        print STDERR "URL ", $url, " was not valid, sorry\n";
        exit(&EINVAL);
    }

    foreach (keys(%values)) {
        $values{$_} = urldecode($values{$_});
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

    # FIXME: Should actually look at $srvInfo->{'NetworkAddresses'}; we
    # could then acquire an IPv6 address (or a v4 address for a server we
    # queried via AppleTalk) and use that...
#    if ($has_IO__Socket__INET6) {
#        my @hosts = map { if ($_->{'family'} == AF_INET6) { $_ } }
#                @{$srvInfo->{'NetworkAddresses'}};
#        print Dumper($srvInfo->{'NetworkAddresses'});
#    }

    my $session;
    if ($values{'atalk_transport'}) {
        $session = new Net::AFP::Atalk($host, $port);
    }
    else {
        $session = new Net::AFP::TCP(@values{'host', 'port'});
    }
    unless (ref($session) and $session->isa('Net::AFP')) {
        print STDERR "Could not connect via AFP to ", $values{'host'}, "\n";
        return &ENODEV;
    }

    my $cv = Net::AFP::Versions::GetPreferredVersion($$srvInfo{'AFPVersions'},
            $values{'atalk_transport'});
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

sub urldecode { # {{{1
    my ($string) = @_;
    if (defined $string) {
        $string =~ tr/+/ /;
        $string =~ s/\%([0-9a-f]{2})/chr(hex($1))/gei;
    }
    return $string;
} # }}}1
