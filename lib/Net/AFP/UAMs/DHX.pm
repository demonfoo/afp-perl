# This package fairly correctly implements the DHX (aka DHCAST128) User
# Authentication Method for AFP sessions. It uses a Diffie-Hellman key
# exchange to establish a keyset that can be used for (reasonably) secure
# password-based authentication without the need for prehashed passwords.
# It requires CryptX for various crypto-related actions.

# This UAM was added as of AFP 3.0. (Later backported to Classic - AFP 2.3?)

package Net::AFP::UAMs::DHX;
use Modern::Perl q{2021};
use diagnostics;
use integer;
use Carp;

use Readonly;
Readonly my $UAMNAME => q{DHCAST128};

# Crypt::Mode::CBC doesn't like if I make these Readonly.
my $C2SIV = q{LWallace};
my $S2CIV = q{CJalbert};

Readonly my $len            => 16;
Readonly my $nonce_len      => 16;
Readonly my $pw_len         => 64;
Readonly my $signature_len  => 16;

# CryptX modules for crypto-related functionality.
use Crypt::Mode::CBC;
use Crypt::PRNG qw(random_bytes);
use Crypt::PK::DH;
use Crypt::Misc qw(increment_octets_be);
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 150);

# These are universal. This particular UAM ALWAYS uses these values - $g
# as the base for an exponentiation, and $p as a modulus.
my $p = q{0xba2873dfb06057d43f2024744ceee75b};
my $g = q{0x07};

# since these parts are the same between authentication and password changing,
# let's not write the whole thing twice, eh?
sub auth_common1 {
    my($session) = @_;

    my $dh = Crypt::PK::DH->new();
    $dh->generate_key({ p => $p, g => $g });

    my $Ma = Net::AFP::UAMs::zeropad($dh->export_key_raw(q{public}), $len);
    if (length($Ma) > $len) {
        $Ma = substr $Ma, length($Ma) - $len, $len;
    }

    return(dh => $dh, Ma => $Ma);
}

sub auth_common2 {
    my($session, %params) = @_;
    $params{store_sesskey} ||= 0;

    my($Mb, $encrypted) = unpack sprintf(q{a[%d]a*}, $len), $params{message};
    my $K = $params{dh}->shared_secret(Crypt::PK::DH->new()
      ->import_key_raw($Mb, q{public}, { p => $p, g => $g }));
    ${$session}{logger}->debug(sub { sprintf q{K is 0x%s}, unpack q{H*}, $K });

    ${$session}{logger}->debug(sub { sprintf q{encrypted is 0x%s},
      unpack q{H*}, $encrypted });

    # Set up an encryption context with the key we derived, and decrypt the
    # ciphertext that the server sent back to us.
    my $key = Net::AFP::UAMs::zeropad($K, $len);
    if ($params{store_sesskey}) {
        ${$session}{SessionKey} = $key;
    }
    undef $K;
    my $ctx = Crypt::Mode::CBC->new(q{CAST5}, 0);
    my $decrypted = $ctx->decrypt($encrypted, $key, $S2CIV);
    ${$session}{logger}->debug(sub { sprintf q{decrypted is 0x%s},
      unpack q{H*}, $decrypted });

    # The nonce is a random value that the server sends as a check; we add
    # one to it, and send it back to the server to prove we understand what
    # it's saying.
    my($nonce, $sig) = unpack sprintf(q{a[%d]a[%d]}, $nonce_len,
      $signature_len), $decrypted;
    # signature should be 16 bytes of null; if it's not something has gone
    # very wrong.
    if ($sig ne qq{\0} x $signature_len) {
        croak(q{encryption error - signature was not what was expected?});
    }
    undef $decrypted;
    ${$session}{logger}->debug(sub { sprintf q{nonce is %s}, unpack q{H*},
      $nonce });
    # If all bits are 1, this will throw a fatal error.
    $nonce = increment_octets_be($nonce);
    ${$session}{logger}->debug(sub { sprintf q{nonce is %s after increment},
      unpack q{H*}, $nonce });
    $nonce = Net::AFP::UAMs::zeropad($nonce, $nonce_len);

    return(nonce => $nonce, key => $key, ctx => $ctx);
}

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa(q{Net::AFP})) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    if (ref($pw_cb) ne q{CODE}) {
        croak(q{Password callback MUST be a subroutine ref});
    }

    my %params = auth_common1($session);

    # Send the "random number" to the server as the first stage of the
    # authentication process, along with the username.
    my(%resp, $rc);

    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                AFPVersion   => $AFPVersion,
                UAM          => $UAMNAME,
                UserName     => $username,
                UserAuthInfo => $params{Ma});
        ${$session}{logger}->info(q{FPLoginExt() completed with result code },
          $rc);
    }
    else {
        my $ai = pack q{C/ax![s]a*}, $username, $params{Ma};
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $ai);
        ${$session}{logger}->info(q{FPLogin() completed with result code },
          $rc);
    }
    return $rc if $rc != $kFPAuthContinue;

    %params = auth_common2($session, message => $resp{UserAuthInfo},
      store_sesskey => 1, dh => $params{dh});

    my $authdata = pack sprintf(q{a[%d]a[%d]}, $nonce_len, $pw_len),
      $params{nonce}, &{$pw_cb}();
    delete $params{nonce};
    my $ciphertext = $params{ctx}->encrypt($authdata, $params{key}, $C2SIV);
    undef $authdata;
    ${$session}{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($resp{ID}, $ciphertext);
    undef $ciphertext;
    ${$session}{logger}->info(sub { sprintf q{FPLoginCont() completed with } .
      q{result code %d}, $rc });
    return $rc;
}

sub ChangePassword {
    my($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa(q{Net::AFP})) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    my %params = auth_common1($session);

    # Send an ID value of 0, followed by our Ma value.
    my $authinfo = pack sprintf(q{na[%d]}, $len), 0, $params{Ma};
    delete $params{Ma};
    ${$session}{logger}->debug(sub { sprintf q{authinfo is 0x%s},
      unpack q{H*}, $authinfo });
    my $resp = undef;

    # Username is always an empty string with AFP 3.0 and up.
    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            $kFPVerAtLeast)) {
        $username = q{};
    }
    my $rc = $session->FPChangePassword($UAMNAME, $username, $authinfo, \$resp);
    undef $authinfo;
    ${$session}{logger}->info(q{FPChangePassword() completed with result },
      q{code }, $rc);
    return $rc if $rc != $kFPAuthContinue;

    my($ID, $message) = unpack q{S>a*}, $resp;
    %params = auth_common2($session, message => $message, dh => $params{dh});

    my $authdata = pack sprintf(q{a[%1$d]a[%2$d]a[%2$d]}, $nonce_len, $pw_len),
      $params{nonce}, $newPassword, $oldPassword;
    delete $params{nonce};
    my $ciphertext = $params{ctx}->encrypt($authdata, $params{key}, $C2SIV);
    undef $authdata;
    ${$session}{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $message = pack q{S>a*}, $ID, $ciphertext;
    ${$session}{logger}->debug(sub { sprintf q{message is 0x%s},
      unpack q{H*}, $message });
    undef $ciphertext;
    $rc = $session->FPChangePassword($UAMNAME, $username, $message);
    undef $message;
    ${$session}{logger}->info(q{FPChangePassword() completed with result },
      q{code }, $rc);
    return $rc;
}

1;
# vim: ts=4 et ai sw=4
