# This package implements the Random Number Exchange User Authentication
# Method for AFP. It uses Crypt::DES for the actual DES encryption used
# as part of the authentication process.
# This UAM is considered deprecated by Apple, and OS X no longer supports
# its use. This is for legacy compatibility only. (Does that apply to
# 2-way randnum as well?)

package Net::AFP::UAMs::Randnum;
use constant UAMNAME => 'Randnum exchange';

use Crypt::DES;
use Net::AFP::Result;
use Net::AFP::Versions;
use strict;
use warnings;

Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 50);

sub Authenticate {
	my($session, $AFPVersion, $username, $pw_cb) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	# Pack just the username into a Pascal-style string, and send that to
	# the server.
	my $resp = undef;
	my $rc = $session->FPLoginExt(0, $AFPVersion, UAMNAME, 3, $username, 3, '',
			undef, \$resp);
	print 'FPLoginExt() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;

	if ($rc == kFPCallNotSupported) {
		my $authinfo = pack('C/a*', $username);
		$rc = $session->FPLogin($AFPVersion, UAMNAME, $authinfo, \$resp);
		print 'FPLogin() completed with result code ', $rc, "\n"
				if defined $::__AFP_DEBUG;
	}

	return $rc unless $rc == kFPAuthContinue;

	# The server will send us a random 8-byte number; take that, and encrypt
	# it with the password the user gave us.
	my ($randnum) = unpack('a8', $resp->{'UserAuthInfo'});
	print '$randnum is 0x', unpack('H*', $randnum), "\n"
			if defined $::__AFP_DEBUG;
	my $deshash = new Crypt::DES(pack('a8', &$pw_cb()));
	my $crypted = $deshash->encrypt($randnum);
	undef $randnum;
	print '$crypted is 0x', unpack('H*', $crypted), "\n"
			if defined $::__AFP_DEBUG;

	# Send the response back to the server, and hope we did this right.
	$rc = $session->FPLoginCont($resp->{'ID'}, $crypted);
	undef $crypted;
	print 'FPLoginCont() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;
	return $rc;
}

sub ChangePassword {
	my ($session, $username, $oldPassword, $newPassword) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	# Establish encryption contexts for each of the supplied passwords. Then
	# pack the old password encrypted with the new one, and the new password
	# encrypted with the old one, as directed.
	my $oldcrypt = new Crypt::DES(pack('a8', $oldPassword));
	my $newcrypt = new Crypt::DES(pack('a8', $newPassword));
	my $message = pack('a8a8', $newcrypt->encrypt($oldPassword),
			$oldcrypt->encrypt($newPassword));
	undef $oldcrypt;
	undef $newcrypt;

	# Send the message to the server, and pass the return code directly
	# back to the caller.
	if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
				Net::AFP::Versions::AtLeast)) {
		$username = '';
	}
	my $rc = $session->FPChangePassword(UAMNAME, $username, $message);
	undef $message;
	print 'FPChangePassword() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;
	return $rc;
}

1;
# vim: ts=4
