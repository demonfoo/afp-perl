# This package implements the plain text password authentication (aka
# Cleartxt Passwrd) UAM for the AFP protocol.

package Net::AFP::UAMs::Plaintext;
use constant UAMNAME => 'Cleartxt Passwrd';

use Net::AFP::Versions;
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

	my $authinfo = substr(pack('xC/a*x![s]a8', $username, &$pw_cb()), 1);
	return $session->FPLogin($AFPVersion, UAMNAME, $authinfo);
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
