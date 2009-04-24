package Net::AFP::UAMs::Kerberos;

use constant UAMNAME => 'Client Krb v2';

use GSSAPI;
use Net::AFP::Result;

use strict;

Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 300);

sub Authenticate {
	my ($session, $AFPVersion, $username, $pw_cb, $realm) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	# FIXME: I think we're supposed to try to get the Kerberos ticket before
	# we attempt to do FPLoginExt()...

	my $resp = '';
	my $rc = $session->FPLoginExt(0, $AFPVersion, UAMNAME, 3, $username,
			3, $realm, undef, \$resp);
	print 'FPLoginExt() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;

	return $rc unless $rc == Net::AFP::Result::kFPAuthContinue;

	if (1) { # using Kerberos v5
		my $message = pack('C/a*x![s]n/a*', $username, $ticket);

	# FIXME: Need to initialize the security context; don't yet know how to
	# do that though, as I've never done Kerberos/GSSAPI programming.

}
die('Incomplete code, should not be used yet');
1;
