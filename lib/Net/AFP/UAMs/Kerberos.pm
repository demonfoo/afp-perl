# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::Kerberos;

use Readonly;
Readonly my $UAMNAME => 'Client Krb v2';

use GSSAPI;
use Net::AFP::Result;
use Net::AFP::TokenTypes;
use Net::AFP;

use strict;

#Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 300);

sub Authenticate {
    my ($session, $AFPVersion, $username, $pw_cb, $realm) = @_;

    # Ensure that we've been handed an appropriate object.
    die('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    die('Password callback MUST be a subroutine ref')
            unless ref($pw_cb) eq 'CODE';

    # Try to get a Kerberos token, if we can...?
    my $ctx;
    my $gss_input_token = q();
    my $status = GSSAPI::Context::init($ctx, GSS_C_NO_CREDENTIAL,
            $realm, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
            0, GSS_C_NO_CHANNEL_BINDINGS, $gss_input_token, my $out_mech,
            my $gss_output_token, my $out_flags, my $out_time);

    $status || gss_exit('CLIENT::Unable to initialize security context', $status);

    # Assuming that succeeded, now we do the first stage of the login process.
    my $resp = '';
    my $rc = $session->FPLoginExt(0, $AFPVersion, $UAMNAME, $kFPUTF8Name,
            $username, $kFPUTF8Name, $realm, undef, \$resp);
    print 'FPLoginExt() completed with result code ', $rc, "\n"
            if defined $::__AFP_DEBUG;

    return $rc unless $rc == $kFPAuthContinue;

    # Now send the Kerberos ticket to the AFP server to be authorized...?
    my $message = pack('C/a*x![s]S>/a*', $username, $gss_output_token);
    my $sresp;
    $rc = $session->FPLoginCont($resp->{ID}, $message, \$sresp);

    return $rc unless $rc == $kFPNoErr;

    # Get an encrypted Kerberos session key from the AFP server.
    my $enc_session_key;
    # FIXME: What should the ID field contain? Docs don't really say...
    $rc = $session->FPGetSessionToken(kGetKerberosSessionKey, 0, q{},
            \$enc_session_key);
    $status = $ctx->unwrap($enc_session_key, my $session_key,
            my $conf_state, my $qop);
    # FIXME: Okay, should have the session key in $session_key! Now, what
    # the fuck do we do with it...
    return $rc;

}

sub gss_exit {
    my $errmsg = shift;
    my $status = shift;

    my @major_errors = $status->generic_message();
    my @minor_errors = $status->specific_message();

    print STDERR "$errmsg:\n";
    foreach my $s (@major_errors) {
        print STDERR "  MAJOR::$s\n";
    }
    foreach my $s (@minor_errors) {
        print STDERR "  MINOR::$s\n";
    }
    return 1;
}

1;
