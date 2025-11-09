# This package describes the versions of the AFP protocol that are known,
# and that are supported by us, as well as providing functions for
# version checking (which can be used for enabling specific features based
# on the protocol version agreed upon).
package Net::AFP::Versions;

use strict;
use warnings;

use Net::AFP::TokenTypes;

use Exporter qw(import);
use Readonly;
use Carp;

our @EXPORT = qw($kFPVerNewerThan $kFPVerAtLeast $kFPVerEqual
                 $kFPVerNoNewerThan $kFPVerOlderThan);

my @versions = (
    # AFP 3.4 only changed an AppleTalk to POSIX error mapping.
    {
        VersionString => q{AFP3.4},
        MajorNumber   => 3,
        MinorNumber   => 4,
        Supported     => 1,
        CanDoAtalk    => 0,
    },
    # AFP 3.3 requires replay cache.
    {
        VersionString => q{AFP3.3},
        MajorNumber   => 3,
        MinorNumber   => 3,
        Supported     => 1,
        CanDoAtalk    => 0,
    },
    {
        VersionString => q{AFP3.2},
        MajorNumber   => 3,
        MinorNumber   => 2,
        Supported     => 1,
        CanDoAtalk    => 0,
    },
    {
        VersionString => q{AFP3.1},
        MajorNumber   => 3,
        MinorNumber   => 1,
        Supported     => 1,
        CanDoAtalk    => 0,
    },
    {
        VersionString => q{AFPX03},
        MajorNumber   => 3,
        MinorNumber   => 0,
        Supported     => 1,
        CanDoAtalk    => 0,
    },
    {
        VersionString => q{AFP2.3},
        MajorNumber   => 2,
        MinorNumber   => 3,
        Supported     => 1,
        CanDoAtalk    => 1,
    },
    {
        VersionString => q{AFP2.2},
        MajorNumber   => 2,
        MinorNumber   => 2,
        Supported     => 1,
        CanDoAtalk    => 1,
    },
    {
        VersionString => q{AFPVersion 2.1},
        MajorNumber   => 2,
        MinorNumber   => 1,
        Supported     => 1,
        CanDoAtalk    => 1,
    },
    {
        VersionString => q{AFPVersion 2.0},
        MajorNumber   => 2,
        MinorNumber   => 0,
        Supported     => 1,
        CanDoAtalk    => 1,
    },
    {
        VersionString => q{AFPVersion 1.1},
        MajorNumber   => 1,
        MinorNumber   => 1,
        Supported     => 1,
        CanDoAtalk    => 1,
    },
);

my %versionmap = map { $_->{VersionString} => $_ } @versions;

Readonly our $kFPVerNewerThan   => 0;
Readonly our $kFPVerAtLeast     => 1;
Readonly our $kFPVerEqual       => 2;
Readonly our $kFPVerNoNewerThan => 3;
Readonly our $kFPVerOlderThan   => 4;

sub CompareByString {
    my($session, $verstring, $cmptype) = @_;

    if (not exists $versionmap{$verstring}) {
        return;
    }
    my($major, $minor) = @{$versionmap{$verstring}}{qw[MajorNumber MinorNumber]};
    return CompareByVersionNum($session, $major, $minor, $cmptype);
}

sub CompareByVersionNum {
    my ($session, $major, $minor, $cmptype) = @_;

    my $ver_str = ref($session) ? $session->{AFPVersion} : $session;
    my $running_ver = $versionmap{$ver_str};
    my($r_major, $r_minor) = @{$running_ver}{qw[MajorNumber MinorNumber]};

    if ($cmptype == $kFPVerNewerThan) {
        return(1) if $r_major > $major;
        return(1) if $r_major == $major && $r_minor > $minor;
        return 0;
    }
    if ($cmptype == $kFPVerAtLeast) {
        return(1) if $r_major > $major;
        return(1) if $r_major == $major && $r_minor >= $minor;
        return 0;
    }
    if ($cmptype == $kFPVerEqual) {
        return(1) if $r_major == $major && $r_minor == $minor;
        return 0;
    }
    if ($cmptype == $kFPVerNoNewerThan) {
        return(0) if $r_major > $major;
        return(0) if $r_major == $major && $r_minor > $minor;
        return 1;
    }
    if ($cmptype == $kFPVerOlderThan) {
        return(0) if $r_major > $major;
        return(0) if $r_major == $major && $r_minor >= $minor;
        return 1;
    }

    croak(q{Invalid comparison type given});
}

sub GetPreferredVersion {
    my($ver_list, $using_atalk) = @_;

    my $best_version;

    foreach my $ver (@{$ver_list}) {
        if (exists $versionmap{$ver}) {
            if (not $versionmap{$ver}{Supported}) {
                next;
            }
            if ($using_atalk and not $versionmap{$ver}{CanDoAtalk}) {
                next;
            }
            if (not defined $best_version) {
                $best_version = $versionmap{$ver};
                next;
            }
            my($b_major, $b_minor) =
                    @{$best_version}{qw[MajorNumber MinorNumber]};
            my($major, $minor) =
                    @{$versionmap{$ver}}{qw[MajorNumber MinorNumber]};

            if (($major > $b_major) ||
                    (($major == $b_major) && ($minor > $b_minor))) {
                $best_version = $versionmap{$ver};
            }
        }
    }
    if (defined $best_version) {
        return $best_version->{VersionString};
    }

    return;
}

1;
# vim: ts=4 ai et fdm=marker
