package Net::AFP::UAMs::Kerberos;

use constant UAMNAME => 'Client Krb v2';

use GSSAPI;
use Net::AFP::Result;
use Net::AFP;

use strict;

#Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 300);

sub Authenticate {
	my ($session, $AFPVersion, $username, $pw_cb, $realm) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP!')
			unless ref($session) and $session->isa('Net::AFP');

	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	# FIXME: I think we're supposed to try to get the Kerberos ticket before
	# we attempt to do FPLoginExt()...

	my $resp = '';
	my $rc = $session->FPLoginExt(0, $AFPVersion, UAMNAME, kFPUTF8Name,
			$username, kFPUTF8Name, $realm, undef, \$resp);
	print 'FPLoginExt() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;

	return $rc unless $rc == kFPAuthContinue;

	my $ctx;
	my $gss_input_token = q();
	my $status = GSSAPI::Context::init($ctx, GSS_C_NO_CREDENTIAL,
			$realm, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
			0, GSS_C_NO_CHANNEL_BINDINGS, $gss_input_token, my $out_mech,
			my $gss_output_token, my $out_flags, my $out_time);

	$status || gss_exit("CLIENT::Unable to initialize security context", $status);

	my $message = pack('C/a*x![s]n/a*', $username, $gss_output_token);
	my $sresp;
	$rc = $session->FPLoginCont($$resp{'ID'}, $message, \$sresp);

	return $rc unless $rc == kFPNoErr;

	($gss_input_token) = unpack('n/a*', $$sresp{'UserAuthInfo'});

	$status = GSSAPI::Context::init($ctx, GSS_C_NO_CREDENTIAL,
			$realm, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
			0, GSS_C_NO_CHANNEL_BINDINGS, $gss_input_token, $out_mech,
			$gss_output_token, $out_flags, $out_time);

	$status || gss_exit("CLIENT::Unable to initialize security context", $status);

	# FIXME: Apple's docs talk about using FPGetSessionToken() about
	# here to get a random session key from the server, and also something
	# about a disconnect token; I'm not really clear here on what I'm
	# supposed to do with all that.
	return $rc;

}
die('Incomplete code, should not be used yet');
1;
