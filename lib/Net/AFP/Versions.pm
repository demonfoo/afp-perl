# This package describes the versions of the AFP protocol that are known,
# and that are supported by us, as well as providing functions for
# version checking (which can be used for enabling specific features based
# on the protocol version agreed upon).
package Net::AFP::Versions;

use Net::AFP::TokenTypes;

use Exporter qw(import);

our @EXPORT = qw(kFPVerNewerThan kFPVerAtLeast kFPVerEqual kFPVerNoNowerThan
				 kFPVerOlderThan);

=head1 NAME

Net::AFP::Versions - AFP version agreement and comparison utility functions

=head1 DESCRIPTION

This package contains several convenience functions for establishing
version agreement with an AFP server, as well as comparing versions
by either major and minor number, or the symbolic version string, for
e.g., enabling features based on the version of the AFP protocol in use.

=cut

our @versions = (
	{
		'VersionString'	=> 'AFP3.3',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 3,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 0,
	},
	{
		'VersionString'	=> 'AFP3.2',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 2,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 0,
	},
	{
		'VersionString'	=> 'AFP3.1',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 1,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 0,
	},
	{
		'VersionString'	=> 'AFPX03',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 0,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 0,
	},
	{
		'VersionString'	=> 'AFP2.3',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 3,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 1,
	},
	{
		'VersionString'	=> 'AFP2.2',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 2,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 1,
	},
	{
		'VersionString'	=> 'AFPVersion 2.1',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 1,
		'Supported'		=> 1,
		'CanDoAtalk'	=> 1,
	},
	{
		'VersionString'	=> 'AFPVersion 2.0',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 0,
		'Supported'		=> 0,
		'CanDoAtalk'	=> 1,
	},
	{
		'VersionString'	=> 'AFPVersion 1.1',
		'MajorNumber'	=> 1,
		'MinorNumber'	=> 1,
		'Supported'		=> 0,
		'CanDoAtalk'	=> 1,
	},
);

our %versionmap = map { $$_{'VersionString'}, $_ } @versions;

=head1 COMPARISON CONSTANTS

For some of the provided functions, the type of version comparison desired
can be indicated with the following constants.

=over

=item kFPVerNewerThan

The protocol version in use for the active connection must be newer than
the one passed.

=cut
use constant kFPVerNewerThan		=> 0;
=item kFPVerAtLeast

The protocol version in use for the active connection must be equivalent
to, or newer than, the one passed.

=cut
use constant kFPVerAtLeast		=> 1;
=item kFPVerEqual

The protocol version in use for the active connection must be exactly
the one passed.

=cut
use constant kFPVerEqual		=> 2;
=item kFPVerNoNewerThan

The protocol version in use for the active connection must be older than
or equivalent to, the one passed.

=cut
use constant kFPVerNoNewerThan	=> 3;
=item kFPVerOlderThan

The protocol version in use for the active connection must be older than
the one passed.

=cut
use constant kFPVerOlderThan	=> 4;

=back

=head1 FUNCTIONS

=over

=item CompareByString()

Compare the AFP version being used in an open AFP session to a given
version string, and determine their relationship.

=over

=item $session

=item $verstring

=item $cmptype

=back

=cut
sub CompareByString {
	my($session, $verstring, $cmptype) = @_;

	return undef unless exists $versionmap{$verstring};
	my($major, $minor) = @{$versionmap{$verstring}}{'MajorNumber', 'MinorNumber'};
	return CompareByVersionNum($session, $major, $minor, $cmptype);
}

=item CompareByVersionNum()

Compare the AFP version being used in an open AFP session to a given
major and minor version number pair, and determine their relationship.

=over

=item $session

=item $major

=item $minor

=item $cmptype

=back

=cut
sub CompareByVersionNum {
	my ($session, $major, $minor, $cmptype) = @_;

	my $ver_str = ref($session) ? $$session{'AFPVersion'} : $session;
	my $running_ver = $versionmap{$ver_str};
	my($r_major, $r_minor) = @$running_ver{'MajorNumber', 'MinorNumber'};

	if ($cmptype == kFPVerNewerThan) {
		return(1) if $r_major > $major;
		return(1) if $r_major == $major && $r_minor > $minor;
		return 0;
	} elsif ($cmptype == kFPVerAtLeast) {
		return(1) if $r_major > $major;
		return(1) if $r_major == $major && $r_minor >= $minor;
		return 0;
	} elsif ($cmptype == kFPVerEqual) {
		return(1) if $r_major == $major && $r_minor == $minor;
		return 0;
	} elsif ($cmptype == kFPVerNoNewerThan) {
		return(0) if $r_major > $major;
		return(0) if $r_major == $major && $r_minor > $minor;
		return 1;
	} elsif ($cmptype == kFPVerOlderThan) {
		return(0) if $r_major > $major;
		return(0) if $r_major == $major && $r_minor >= $minor;
		return 1;
	}

	die("Invalid comparison type given");
}

=item GetPreferredVersion()

Given a list of version strings, pick the highest supported one, and return
it to the caller.

=over

=item $ver_list

=back

=cut
sub GetPreferredVersion {
	my($ver_list, $using_atalk) = @_;

	my $best_version;

	foreach my $ver (@$ver_list) {
		if (exists $versionmap{$ver}) {
			next unless $versionmap{$ver}{'Supported'};
			next if $using_atalk and !$versionmap{$ver}{'CanDoAtalk'};
			unless (defined $best_version) {
				$best_version = $versionmap{$ver};
				next;
			}
			my($b_major, $b_minor) =
					@$best_version{'MajorNumber', 'MinorNumber'};
			my($major, $minor) =
					@{$versionmap{$ver}}{'MajorNumber', 'MinorNumber'};

			if (($major > $b_major) ||
					(($major == $b_major) && ($minor > $b_minor))) {
				$best_version = $versionmap{$ver};
			}
		}
	}
	if (defined $best_version) {
		return $$best_version{'VersionString'};
	}

	return undef;
}

=back

=cut
1;
# vim: ts=4 ai fdm=marker
