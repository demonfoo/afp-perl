# This package fairly correctly implements the DHX (aka DHCAST128) User
# Authentication Method for AFP sessions. It uses a Diffie-Hellman key
# exchange to establish a keyset that can be used for (reasonably) secure
# password-based authentication without the need for prehashed passwords.
# It requires the Crypt::CBC module to provide a cipher-block-chaining
# layer, and Crypt::CAST5 to provide the CAST5 (aka CAST128) encryption
# method used to secure the data over the wire. Math::BigInt::GMP is
# recommended for fast large-integer operations, as Math::BigInt::Calc
# works but is quite slow.

# This UAM was added as of AFP 3.0. (Later backported to Classic - AFP 2.3?)

package Net::AFP::UAMs::DHX;
use Modern::Perl '2021';
use diagnostics;
use integer;
use Carp;
use Bytes::Random::Secure qw(random_bytes);

use Readonly;
Readonly my $UAMNAME => 'DHCAST128';

Readonly my $C2SIV => 'LWallace';
Readonly my $S2CIV => 'CJalbert';

Readonly my $len => 16;
Readonly my $nonce_len => 16;
Readonly my $pw_len => 64;

# Provides the encryption algorithm.
my $has_Crypt__CAST5_PP = 0;
eval {
    require Crypt::CAST5_PP;
    1;
} and do {
    $has_Crypt__CAST5_PP = 1;
};

my $has_Crypt__CAST5 = 0;
eval {
    require Crypt::CAST5;
    1;
} and do {
    $has_Crypt__CAST5 = 1;
};
croak("No CAST5 implementation was available?")
        unless $has_Crypt__CAST5 || $has_Crypt__CAST5_PP;
# Provides the cipher-block chaining layer over the encryption algorithm.
use Crypt::CBC;
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
# Provides large-integer mathematics features, necessary for the
# cryptographic exchanges and derivation of the key. Fast, but the
# non-threaded to threaded changeover hoses it, so don't create Math::BigInt
# objects until after threads are started.
use Math::BigInt lib => 'GMP';
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 150);

# These are universal. This particular UAM ALWAYS uses these values - $g
# as the base for an exponentiation, and $p as a modulus.
my @p_bytes = (0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57, 0xd4, 0x3f, 0x20,
               0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b);
my @g_bytes = (0x07);

sub zeropad { return("\0" x ($_[1] - length($_[0])) . $_[0]); }

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    croak(q{Object MUST be of type Net::AFP!})
            unless ref($session) and $session->isa('Net::AFP');

    croak(q{Password callback MUST be a subroutine ref})
            if ref($pw_cb) ne q{CODE};

    # Moving these into the functions, to make Math::BigInt::GMP happy.
    my $p = Math::BigInt->from_bytes(pack('C*', @p_bytes));
    my $g = Math::BigInt->from_bytes(pack('C*', @g_bytes));

    my $nonce_limit = Math::BigInt->bone();
    $nonce_limit->blsft($nonce_len * 8);

    # Get random bytes that constitute a large exponent for the random number
    # exchange we do.
    my $Ra = Math::BigInt->from_bytes(random_bytes(32));
    $session->{logger}->debug('$Ra is ', $Ra->as_hex());

    # Ma = g^Ra mod p <- This gives us the "random number" that we hand to
    # the server.
    my $Ma = $g->bmodpow($Ra, $p);
    $session->{logger}->debug('$Ma is ', $Ma->as_hex());

    # Send the "random number" to the server as the first stage of the
    # authentication process, along with the username.
    my $authinfo = pack('C/a*x![s]a*', $username, zeropad($Ma->to_bytes(), $len));
    $session->{logger}->debug('$authinfo is 0x', unpack('H*', $authinfo));
    my %resp;
    my $rc;
    
    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                AFPVersion   => $AFPVersion,
                UAM          => $UAMNAME,
                UserName     => $username,
                UserAuthInfo => zeropad($Ma->to_bytes(), $len));
        $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);
    }
    else {
        my $ai = pack('C/a*x![s]a*', $username, zeropad($Ma->to_bytes(), $len));
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $ai);
        $session->{logger}->debug('FPLogin() completed with result code ', $rc);
    }
    undef $Ma;
    undef $authinfo;
    return $rc if $rc != $kFPAuthContinue;
    my $Mb = Math::BigInt->from_bytes(unpack('a' . $len, $resp{UserAuthInfo}));
    $session->{logger}->debug('$Mb is ', $Mb->as_hex());
    my $message = unpack('x' . $len . 'a*', $resp{UserAuthInfo});
    $session->{logger}->debug('$message is 0x', unpack('H*', $message));

    # K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
    # and decrypt ciphertext for communicating with the server.
    my $K = $Mb->bmodpow($Ra, $p);
    undef $Ra;
    undef $Mb;
    $session->{logger}->debug('$K is ', $K->as_hex());

    # Set up an encryption context with the key we derived, and decrypt the
    # ciphertext that the server sent back to us.
    $session->{SessionKey} = zeropad($K->to_bytes(), $len);
    my $ctx = Crypt::CBC->new({ key     => $session->{SessionKey},
                                cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                padding => 'none',
                                pbkdf   => 'none',
                                header  => 'none',
                                iv      => $S2CIV });
    undef $K;
    my $decrypted = $ctx->decrypt($message);
    $session->{logger}->debug('$decrypted is 0x', unpack('H*', $decrypted));

    # The nonce is a random value that the server sends as a check; we add
    # one to it, and send it back to the server to prove we understand what
    # it's saying.
    my $nonce = Math::BigInt->from_bytes(unpack('a' . $nonce_len, $decrypted));
    undef $decrypted;
    $session->{logger}->debug('$nonce is ', $nonce->as_hex());
    $nonce->binc();
    $nonce = $nonce->bmod($nonce_limit);
    $session->{logger}->debug('$nonce is ', $nonce->as_hex(), " after increment");
    my $authdata = pack('a[' . $nonce_len . ']a[' . $pw_len . ']',
	                zeropad($nonce->to_bytes(), $nonce_len), &{$pw_cb}());
    undef $nonce;
    $ctx->set_initialization_vector($C2SIV);
    my $ciphertext = $ctx->encrypt($authdata);
    undef $authdata;
    $session->{logger}->debug('$ciphertext is 0x', unpack('H*', $ciphertext));

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($resp{ID}, $ciphertext);
    undef $ciphertext;
    $session->{logger}->debug('FPLoginCont() completed with result code ', $rc);
    return $rc;
}

sub ChangePassword {
    my($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    croak('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    # Moving these into the functions, to make Math::BigInt::GMP happy.
    my $p = Math::BigInt->from_bytes(pack('C*', @p_bytes));
    my $g = Math::BigInt->from_bytes(pack('C*', @g_bytes));

    my $nonce_limit = Math::BigInt->bone();
    $nonce_limit->blsft($nonce_len * 8);

    # Get random bytes that constitute a large exponent for the random number
    # exchange we do.
    my $Ra = Math::BigInt->from_bytes(random_bytes(32));
    $session->{logger}->debug('$Ra is ', $Ra->as_hex());

    # Ma = g^Ra mod p <- This gives us the "random number" that we hand to
    # the server.
    my $Ma = $g->bmodpow($Ra, $p);
    $session->{logger}->debug('$Ma is ', $Ma->as_hex());

    # Send an ID value of 0, followed by our Ma value.
    my $authinfo = pack('na[' . $len . ']', 0, zeropad($Ma->to_bytes(), $len));
    undef $Ma;
    $session->{logger}->debug('$authinfo is 0x', unpack('H*', $authinfo));
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

    # Unpack the server response for our perusal.
    my $Mb = Math::BigInt->from_bytes(unpack('x2a' . $len, $resp));
    $session->{logger}->debug('$Mb is ', $Mb->as_hex());

    # K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
    # and decrypt ciphertext for communicating with the server.
    my $K = $Mb->bmodpow($Ra, $p);
    undef $Ra;
    undef $Mb;
    $session->{logger}->debug('$K is ', $K->as_hex());

    # Set up an encryption context with the key we derived, and decrypt the
    # ciphertext that the server sent back to us.
    my $ctx = Crypt::CBC->new({ key     => zeropad($K->to_bytes(), $len),
                                cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                padding => 'none',
                                pbkdf   => 'none',
                                header  => 'none',
                                iv      => $S2CIV });
    undef $K;
    my $decrypted = $ctx->decrypt(unpack('x2x' . $len . 'a32', $resp));
    $session->{logger}->debug('$decrypted is 0x', unpack('H*', $decrypted));

    # The nonce is a random value that the server sends as a check; we add
    # one to it, and send it back to the server to prove we understand what
    # it's saying.
    my $nonce = Math::BigInt->from_bytes(unpack('a' . $nonce_len, $decrypted));
    undef $decrypted;
    $session->{logger}->debug('$nonce is ', $nonce->as_hex());
    $nonce->binc();
    $nonce = $nonce->bmod($nonce_limit);
    $session->{logger}->debug('$nonce is ', $nonce->as_hex(), " after increment");
    my $authdata = pack('a[' . $nonce_len . ']a[' . $pw_len . ']a[' . $pw_len . ']',
	                zeropad($nonce->to_bytes(), $nonce_len), $newPassword,
                    $oldPassword);
    undef $nonce;
    $ctx->set_initialization_vector($C2SIV);
    my $ciphertext = $ctx->encrypt($authdata);
    undef $authdata;
    $session->{logger}->debug('$ciphertext is 0x', unpack('H*', $ciphertext));

    # Send the response back to the server, and hope we did this right.
    my $message = pack('na*', unpack('n', $resp), $ciphertext);
    $session->{logger}->debug('$message is 0x', unpack('H*', $message));
    undef $ciphertext;
    $rc = $session->FPChangePassword($UAMNAME, $username, $message);
    undef $message;
    $session->{logger}->debug('FPChangePassword() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
