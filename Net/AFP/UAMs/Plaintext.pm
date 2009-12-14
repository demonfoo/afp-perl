# This package implements the plain text password authentication (aka
# Cleartxt Passwrd) UAM for the AFP protocol.

package Net::AFP::UAMs::Plaintext;
use constant UAMNAME => 'Cleartxt Passwrd';

use Net::AFP::Versions;
use Net::AFP::Result;
use strict;
use warnings;

Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 0);

sub Authenticate {
	my($session, $AFPVersion, $username, $pw_cb) = @_;

	# Ensure that we've been handed an appropriate object.
	die("Object MUST be of type Net::AFP::Connection!")
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');
	
	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	my $pw_data = pack('a8', &$pw_cb());
	my $rc = $session->FPLoginExt(0, $AFPVersion, UAMNAME, 3, $username, 3, '',
			$pw_data);
	print 'FPLoginExt() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;

	if ($rc == kFPCallNotSupported) {
		my $authinfo = substr(pack('xC/a*x![s]a8', $username, $pw_data), 1);
		$rc = $session->FPLogin($AFPVersion, UAMNAME, $authinfo);
		print 'FPLogin() completed with result code ', $rc, "\n"
				if defined $::__AFP_DEBUG;
	}

	return $rc;
}

sub ChangePassword {
	my ($session, $username, $oldPassword, $newPassword) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
				Net::AFP::Versions::AtLeast)) {
		$username = '';
	}
	return $session->FPChangePassword(UAMNAME, $username,
			pack('a8', $newPassword));
}

1;
# vim: ts=4
