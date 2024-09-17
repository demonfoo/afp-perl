# This package fairly correctly implements the DHX (aka DHCAST128) User
# Authentication Method for AFP sessions. It uses a Diffie-Hellman key
# exchange to establish a keyset that can be used for (reasonably) secure
# password-based authentication without the need for prehashed passwords.
# It requires CryptX for various crypto-related actions.

# This UAM was added as of AFP 3.0. (Later backported to Classic - AFP 2.3?)

package Net::AFP::UAMs::DHX;
use Modern::Perl '2021';
use diagnostics;
use integer;
use Carp;

use Readonly;
Readonly my $UAMNAME => 'DHCAST128';

# Crypt::Mode::CBC doesn't like if I make these Readonly.
my $C2SIV = 'LWallace';
my $S2CIV = 'CJalbert';

Readonly my $len       => 16;
Readonly my $nonce_len => 16;
Readonly my $pw_len    => 64;

# CryptX modules for crypto-related functionality.
use Crypt::Mode::CBC;
use Crypt::PRNG qw(random_bytes);
use Crypt::DH::GMP;
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
use Math::BigInt;
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 150);

# These are universal. This particular UAM ALWAYS uses these values - $g
# as the base for an exponentiation, and $p as a modulus.
my @p_bytes = (0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57, 0xd4, 0x3f, 0x20,
               0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b,);
my @g_bytes = (0x07);

##no critic qw(RequireArgUnpacking)
sub zeropad {
    if (length($_[0]) > $_[1]) {
        return substr $_[0], length($_[0]) - $_[1], $_[1];
    }
    else {
        return("\0" x ($_[1] - length $_[0]) . $_[0]);
    }
}

# since these parts are the same between authentication and password changing,
# let's not write the whole thing twice, eh?
sub auth_common1 {
    my($session) = @_;

    my $dh = Crypt::DH::GMP->new(
            p => '0x' . unpack(q{H*}, pack q{C*}, @p_bytes),
            g => '0x' . unpack q{H*}, pack q{C*}, @g_bytes);
    $dh->generate_keys();

    my $Ma = zeropad(pack('B*', $dh->pub_key_twoc()), $len);
    if (length($Ma) > $len) {
        $Ma = substr $Ma, length($Ma) - $len, $len;
    }

    return($dh, $Ma);
}

sub auth_common2 {
    my($session, $message, $len, $store_sesskey, $dh) = @_;

    my $nonce_limit = Math::BigInt->bone();
    $nonce_limit->blsft($nonce_len * 8);

    my($Mb, $encrypted) = unpack "a[${len}]a*", $message;
    my $K = pack q{B*}, $dh->compute_key_twoc('0x' . unpack'H*', $Mb);
    $session->{logger}->debug(sub { sprintf q{K is 0x%s}, unpack q{H*}, $K });

    $session->{logger}->debug(sub { sprintf q{encrypted is 0x%s},
      unpack q{H*}, $encrypted });

    # Set up an encryption context with the key we derived, and decrypt the
    # ciphertext that the server sent back to us.
    my $key = zeropad($K, $len);
    if ($store_sesskey) {
        $session->{SessionKey} = $key;
    }
    undef $K;
    my $ctx = Crypt::Mode::CBC->new('CAST5', 0);
    my $decrypted = $ctx->decrypt($encrypted, $key, $S2CIV);
    $session->{logger}->debug(sub { sprintf q{decrypted is 0x%s},
      unpack q{H*}, $decrypted });

    # The nonce is a random value that the server sends as a check; we add
    # one to it, and send it back to the server to prove we understand what
    # it's saying.
    my($nonce, $sig) = unpack "a[${nonce_len}]a[16]", $decrypted;
    $nonce = Math::BigInt->from_bytes($nonce);
    # signature should be 16 bytes of null; if it's not something has gone
    # very wrong.
    if ($sig ne qq{\0} x 16) {
        croak('encryption error - signature was not what was expected?');
    }
    undef $decrypted;
    $session->{logger}->debug(sub { sprintf q{nonce is %s}, $nonce->as_hex() });
    $nonce->binc();
    $nonce = $nonce->bmod($nonce_limit);
    $session->{logger}->debug(sub { sprintf q{nonce is %s after increment},
      $nonce->as_hex() });

    return($nonce, $key, $ctx);
}

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa('Net::AFP')) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    if (ref($pw_cb) ne q{CODE}) {
        croak(q{Password callback MUST be a subroutine ref});
    }

    my($dh, $Ma) = auth_common1($session);

    # Send the "random number" to the server as the first stage of the
    # authentication process, along with the username.
    my %resp;
    my $rc;

    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                AFPVersion   => $AFPVersion,
                UAM          => $UAMNAME,
                UserName     => $username,
                UserAuthInfo => $Ma);
        $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);
    }
    else {
        my $ai = pack q{C/a*x![s]a*}, $username, $Ma;
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $ai);
        $session->{logger}->debug('FPLogin() completed with result code ', $rc);
    }
    return $rc if $rc != $kFPAuthContinue;

    my($nonce, $key, $ctx) =
      auth_common2($session, $resp{UserAuthInfo}, $len, 1, $dh);

    my $authdata = pack "a[${nonce_len}]a[${pw_len}]",
	                zeropad($nonce->to_bytes(), $nonce_len), &{$pw_cb}();
    undef $nonce;
    my $ciphertext = $ctx->encrypt($authdata, $key, $C2SIV);
    undef $authdata;
    $session->{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($resp{ID}, $ciphertext);
    undef $ciphertext;
    $session->{logger}->debug(sub { sprintf q{FPLoginCont() completed with } .
      q{result code %d}, $rc });
    return $rc;
}

sub ChangePassword {
    my($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa('Net::AFP')) {
        croak('Object MUST be of type Net::AFP!');
    }

    my($dh, $Ma) = auth_common1($session);

    # Send an ID value of 0, followed by our Ma value.
    my $authinfo = pack "na[${len}]", 0, $Ma;
    undef $Ma;
    $session->{logger}->debug(sub { sprintf q{authinfo is 0x%s},
      unpack q{H*}, $authinfo });
    my $resp = undef;

    # Username is always an empty string with AFP 3.0 and up.
    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            $kFPVerAtLeast)) {
        $username = q{};
    }
    my $rc = $session->FPChangePassword($UAMNAME, $username, $authinfo, \$resp);
    undef $authinfo;
    $session->{logger}->debug('FPChangePassword() completed with result code ', $rc);
    return $rc if $rc != $kFPAuthContinue;

    my($ID, $message) = unpack q{S>a*}, $resp;
    my($nonce, $key, $ctx) =
      auth_common2($session, $message, $len, 0, $dh);

    my $authdata = pack "a[${nonce_len}]a[${pw_len}]a[${pw_len}]",
	                zeropad($nonce->to_bytes(), $nonce_len), $newPassword,
                    $oldPassword;
    undef $nonce;
    my $ciphertext = $ctx->encrypt($authdata, $key, $C2SIV);
    undef $authdata;
    $session->{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $message = pack q{S>a*}, $ID, $ciphertext;
    $session->{logger}->debug(sub { sprintf q{message is 0x%s},
      unpack q{H*}, $message });
    undef $ciphertext;
    $rc = $session->FPChangePassword($UAMNAME, $username, $message);
    undef $message;
    $session->{logger}->debug('FPChangePassword() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
