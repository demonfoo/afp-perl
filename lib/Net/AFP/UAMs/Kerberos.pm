# This UAM was added as of AFP 3.1.
package Net::AFP::UAMs::Kerberos;

use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'Client Krb v2';

use GSSAPI;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::AFP::TokenTypes;
use Net::AFP::SrvParms;
use Net::AFP;
use Data::Dumper;
use Carp qw(croak);

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 300);

sub Authenticate {
    my ($session, $AFPVersion, $username, $pw_cb, $realm) = @_;

    # Ensure that we've been handed an appropriate object.
    croak('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    croak('Password callback MUST be a subroutine ref')
            unless ref($pw_cb) eq 'CODE';

    my $srvInfo;
    my $result = $session->FPGetSrvrInfo($srvInfo);
    if (!($srvInfo->{Flags} & $kSupportsDirServices)) {
        $session->{logger}->error('AFP server does not support KRB/dir services');
        return $kFPBadUAM;
    }
    my $principal = $srvInfo->{DirectoryNames}[0];

    # Try to get a Kerberos token, if we can...?
    my $ctx = GSSAPI::Context->new;
    my $target;
    my $cred = GSS_C_NO_CREDENTIAL;
    my $status = GSSAPI::Name->import($target, $principal, gss_nt_service_name)
        or return $kFPMiscErr;

    my $outtok;
    my $inflags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
    my $outflags;
    my $challenge = q{};
    $status = $ctx->init($cred, $target, gss_mech_krb5, $inflags, 0,
                GSS_C_NO_CHANNEL_BINDINGS, $challenge, undef, $outtok,
                $outflags, undef);

    $session->{logger}->debug(sprintf('state(0): %s; %s; output token sz: %d',
                    $status->generic_message, $status->specific_message, length($outtok)));

    if (GSSAPI::Status::GSS_ERROR($status->major)) {
        $session->{logger}->error("GSSAPI Error (init): " . $status);
        return $kFPMiscErr;
    }

    if ($status->major == GSS_S_COMPLETE) {
        $session->{logger}->info('GSSAPI auth complete (we think)?');
    }

    # Assuming that succeeded, now we do the first stage of the login process.
    my $resp = q{};
    my $rc = $session->FPLoginExt(0, $AFPVersion, $UAMNAME, $kFPUTF8Name,
            $username, $kFPUTF8Name, $realm, undef, \$resp);
    $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);

    return $rc unless $rc == $kFPAuthContinue;

    # Now send the Kerberos ticket to the AFP server to be authorized...?
    my $message = pack('C/a*x![s]S>/a*', $username, $outtok);
    my $sresp;
    # FIXME: I guess if we're using Kerberos v4, no ID should be passed,
    # but how would I know? Apparently OS X only supports v5...
    $rc = $session->FPLoginCont($resp->{ID}, $message, \$sresp);
    print Dumper(\$sresp);

    return $rc unless $rc == $kFPNoErr;

    # Get an encrypted Kerberos session key from the AFP server.
    my $enc_session_key;
    my $stamp = time() - globalTimeOffset;
    $rc = $session->FPGetSessionToken($kGetKerberosSessionKey, $stamp, q{},
            \$enc_session_key);
    $status = $ctx->unwrap($enc_session_key, my $session_key,
            undef, undef);
    if (!$status) {
        $session->{logger}->error('GSSAPI Error (decode): ' . $status);
        return $kFPMiscErr;
    }
    # FIXME: Okay, should have the session key in $session_key! Now, what
    # the fuck do we do with it...
    $session->{SessionKey} = $session_key;
    return $kFPNoErr;
}

1;
