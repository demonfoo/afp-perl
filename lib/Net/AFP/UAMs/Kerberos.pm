# This UAM was added as of AFP 3.1.
package Net::AFP::UAMs::Kerberos;

use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => q{Client Krb v2};

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
    if (not ref $session or not $session->isa(q{Net::AFP})) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    if (ref($pw_cb) ne q{CODE}) {
        croak(q{Password callback MUST be a subroutine ref});
    }

    my $srvInfo;
    my $result = $session->FPGetSrvrInfo($srvInfo);
    if (!($srvInfo->{Flags} & $kSupportsDirServices)) {
        $session->{logger}->error(q{AFP server does not support KRB/dir services});
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

    $session->{logger}->debug(sprintf q{state(0): %s; %s; output token sz: %d},
      $status->generic_message, $status->specific_message, length $outtok);

    if (GSSAPI::Status::GSS_ERROR($status->major)) {
        $session->{logger}->error(q{GSSAPI Error (init): } . $status);
        return $kFPMiscErr;
    }

    if ($status->major == GSS_S_COMPLETE) {
        $session->{logger}->info(q{GSSAPI auth complete (we think)?});
    }

    # Assuming that succeeded, now we do the first stage of the login process.
    my $resp = q{};
    my($rc, %resp) = $session->FPLoginExt(
        AFPVersion   => $AFPVersion,
        UAM          => $UAMNAME,
        UserName     => $username,
        PathName     => $realm);
    $session->{logger}->debug(q{FPLoginExt() completed with result code },
      $rc);

    if ($rc != $kFPAuthContinue) {
        return $rc;
    }

    # Now send the Kerberos ticket to the AFP server to be authorized...?
    my $message = pack q{C/ax![s]S>/a}, $username, $outtok;
    my $sresp;
    # FIXME: I guess if we're using Kerberos v4, no ID should be passed,
    # but how would I know? Apparently OS X only supports v5...
    $rc = $session->FPLoginCont($resp{ID}, $message, \$sresp);
    print Dumper(\$sresp);

    if ($rc != $kFPNoErr) {
        return $rc;
    }

    # Get an encrypted Kerberos session key from the AFP server.
    my $enc_session_key;
    my $stamp = time() - globalTimeOffset;
    $rc = $session->FPGetSessionToken($kGetKerberosSessionKey, $stamp, q{},
            \$enc_session_key);
    $status = $ctx->unwrap($enc_session_key, my $session_key,
            undef, undef);
    if (!$status) {
        $session->{logger}->error(q{GSSAPI Error (decode): } . $status);
        return $kFPMiscErr;
    }
    # FIXME: Okay, should have the session key in $session_key! Now, what
    # the fuck do we do with it...
    $session->{SessionKey} = $session_key;
    return $kFPNoErr;
}

1;
