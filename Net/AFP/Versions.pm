# This package describes the versions of the AFP protocol that are known,
# and that are supported by us, as well as providing functions for
# version checking (which can be used for enabling specific features based
# on the protocol version agreed upon).

=head1 NAME

Net::AFP::Versions - AFP version agreement and comparison utility functions

=head1 DESCRIPTION

This package contains several convenience functions for establishing
version agreement with an AFP server, as well as comparing versions
by either major and minor number, or the symbolic version string, for
e.g., enabling features based on the version of the AFP protocol in use.

=cut
package Net::AFP::Versions;

our @versions = (
	{
		'VersionString'	=> 'AFP3.3',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 3,
		'Supported'		=> 0,
	},
	{
		'VersionString'	=> 'AFP3.2',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 2,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFP3.1',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 1,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFPX03',
		'MajorNumber'	=> 3,
		'MinorNumber'	=> 0,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFP2.3',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 3,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFP2.2',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 2,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFPVersion 2.1',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 1,
		'Supported'		=> 1,
	},
	{
		'VersionString'	=> 'AFPVersion 2.0',
		'MajorNumber'	=> 2,
		'MinorNumber'	=> 0,
		'Supported'		=> 0,
	},
	{
		'VersionString'	=> 'AFPVersion 1.1',
		'MajorNumber'	=> 1,
		'MinorNumber'	=> 1,
		'Supported'		=> 0,
	},
);

our %versionmap = map { $$_{'VersionString'}, $_ } @versions;

=head1 COMPARISON CONSTANTS

For some of the provided functions, the type of version comparison desired
can be indicated with the following constants.

=over

=item NewerThan

The protocol version in use for the active connection must be newer than
the one passed.

=cut
use constant NewerThan		=> 0;
=item AtLeast

The protocol version in use for the active connection must be equivalent
to, or newer than, the one passed.

=cut
use constant AtLeast		=> 1;
=item Equal

The protocol version in use for the active connection must be exactly
the one passed.

=cut
use constant Equal			=> 2;
=item NoNewerThan

The protocol version in use for the active connection must be older than
or equivalent to, the one passed.

=cut
use constant NoNewerThan	=> 3;
=item OlderThan

The protocol version in use for the active connection must be older than
the one passed.

=cut
use constant OlderThan		=> 4;

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

	my $running_ver = $versionmap{$$session{'AFPVersion'}};
	my($r_major, $r_minor) = @$running_ver{'MajorNumber', 'MinorNumber'};

	if ($cmptype == NewerThan) {
		return(1) if $r_major > $major;
		return(1) if $r_major == $major && $r_minor > $minor;
		return 0;
	} elsif ($cmptype == AtLeast) {
		return(1) if $r_major > $major;
		return(1) if $r_major == $major && $r_minor >= $minor;
		return 0;
	} elsif ($cmptype == Equal) {
		return(1) if $r_major == $major && $r_minor == $minor;
		return 0;
	} elsif ($cmptype == NoNewerThan) {
		return(0) if $r_major > $major;
		return(0) if $r_major == $major && $r_minor > $minor;
		return 1;
	} elsif ($cmptype == OlderThan) {
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
	my($ver_list) = @_;

	my $best_version;

	foreach my $ver (@$ver_list) {
		if (exists $versionmap{$ver}) {
			next unless $versionmap{$ver}{'Supported'};
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
# vim: ts=4
