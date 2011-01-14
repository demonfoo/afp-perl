# This package fairly correctly implements the DHX2 User Authentication Method
# for AFP sessions. It requires the Crypt::CBC module to provide a
# cipher-block-chaining layer, and Crypt::CAST5 to provide the CAST5 (aka
# CAST128) encryption method used to secure the data over the wire.
# Math::BigInt::GMP is strongly recommended for fast large-integer
# operations; the values this UAM deals with are much larger than the older
# DHCAST128 UAM, causing the authentication process to be very slow with
# Math::BigInt::Calc.

# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::DHX2;

use strict;
use warnings;

use constant UAMNAME => 'DHX2';

use constant C2SIV => 'LWallace';
use constant S2CIV => 'CJalbert';

# Provides the encryption algorithm.
my $has_Crypt__CAST5_PP = 0;
eval {
    require Crypt::CAST5_PP;
    1;
} and do {
    $has_Crypt__CAST5_PP = 1;
    Crypt::CAST5_PP->import;
};

my $has_Crypt__CAST5 = 0;
eval {
    require Crypt::CAST5;
    1;
} and do {
    $has_Crypt__CAST5 = 1;
    Crypt::CAST5->import;
};
die("No CAST5 implementation was available?")
        unless $has_Crypt__CAST5 || $has_Crypt__CAST5_PP;

# Provides the cipher-block chaining layer over the encryption algorithm.
use Crypt::CBC;
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
# Provides large-integer mathematics features, necessary for the
# cryptographic exchanges and derivation of the key.
use Math::BigInt lib => 'GMP';
use Digest::MD5 qw(md5);
use Net::AFP::Versions;
use Log::Log4perl qw(:easy);

Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 200);

sub zeropad { return('0' x ($_[1] - length($_[0])) . $_[0]); }

# Variables used by the DHX2 UAM
# +-------------+-------------------------------------------------------------+
# | Value       | Meaning                                                     |
# +-------------+-------------------------------------------------------------+
# | password    | User password padded with nulls to 256 bytes.               |
# +-------------+-------------------------------------------------------------+
# | username    | Pascal string (pstring), padded to an even byte length      |
# +-------------+-------------------------------------------------------------+
# | AFP Vers    | Pascal string (pstring) denoting the version of the AFP     |
# |             | protocol used for the session.                              |
# +-------------+-------------------------------------------------------------+
# | ID          | A two-byte number used by the server to keep track of the   |
# |             | login/change password request. The server may send any two- |
# |             | byte number, the client passes it back unchanged.           |
# +-------------+-------------------------------------------------------------+
# | ID + 1      | The ID incremented by one.                                  |
# +-------------+-------------------------------------------------------------+
# | clientNonce | A 16-byte random number used in the key verification        |
# |             | portion of the exchange.                                    |
# +-------------+-------------------------------------------------------------+
# | serverNonce | A 16-byte random number used in the key verification        |
# |             | portion of the exchange.                                    |
# +-------------+-------------------------------------------------------------+
# | clientNonce | The clientNonce incremented by one.                         |
# | + 1         |                                                             |
# +-------------+-------------------------------------------------------------+
# | MD5(data)   | Take the MD5 hash of the data, which results in a 16-byte   |
# |             | (128 bit) value.                                            |
# +-------------+-------------------------------------------------------------+
# | p           | A variable length prime number (at minimum 512 bits in      |
# |             | size) satisfying the property that (p - 1)/2 is also a      |
# |             | prime (called a Sophie Germain prime) sent by the server    |
# |             | to the client. (Two byte length followed by data.)          |
# +-------------+-------------------------------------------------------------+
# | g           | A small number that is primitive mod p sent by the server   |
# |             | to the client. (Four bytes.)                                |
# +-------------+-------------------------------------------------------------+
# | x^y         | Raise x to the yth power.                                   |
# +-------------+-------------------------------------------------------------+
# | Ra          | An x bit random number used internally by the client.       |
# +-------------+-------------------------------------------------------------+
# | Rb          | An x bit random number used internally by the server.       |
# +-------------+-------------------------------------------------------------+
# | Ma          | g^Ra mod p (sent by the client to the server); the same     |
# |             | number of bytes as p, padded with nulls at the MSB end.     |
# +-------------+-------------------------------------------------------------+
# | Mb          | g^Rb mod p (sent by the server to the client); the same     |
# |             | number of bytes as p, padded with nulls at the MSB end.     |
# +-------------+-------------------------------------------------------------+
# | x           | The size of p in bits.                                      |
# +-------------+-------------------------------------------------------------+
# | len         | The size of p & Ma & Mb in bytes; a two-byte value.         |
# +-------------+-------------------------------------------------------------+
# | K           | Key = MD5(Mb^Ra mod p) = MD5(Ma^Rb mod p)                   |
# +-------------+-------------------------------------------------------------+
# | (dataBytes, | Encrypt dataBytes using CAST 128 CBC using initialization   |
# | IV)K        | vector (IV)                                                 |
# +-------------+-------------------------------------------------------------+
# | C2SIV       | Client-to-server initialization vector.                     |
# +-------------+-------------------------------------------------------------+
# | S2CIV       | Server-to-client initialization vector.                     |
# +-------------+-------------------------------------------------------------+

# Login sequence using DHX2:
# +---------+-----------------+----------------------------------------------+
# | Message | Sender/Receiver | Content                                      |
# +---------+-----------------+----------------------------------------------+
# | 1       | Client->Server  | FPLogin (2 bytes)/AFP Vers/'DHX2'/           |
# |         |                 |       Username (padded)                      |
# +---------+-----------------+----------------------------------------------+
# | 2       | Server->Client  | ID/g/len/p/Mb/and a result code              |
# +---------+-----------------+----------------------------------------------+
# | 3       | Client->Server  | FPLoginCont (2 bytes)/ID/Ma/(clientNonce,    |
# |         |                 |       C2SIV)K                                |
# +---------+-----------------+----------------------------------------------+
# | 4       | Server->Client  | ID + 1/(clientNonce + 1, serverNonce,        |
# |         |                 |       S2CIV)K/and a result code              |
# +---------+-----------------+----------------------------------------------+
# | 5       | Client->Server  | FPLoginCont (2 bytes)/ID + 1/                |
# |         |                 |       (serverNonce + 1, password, S2CIV)K    |
# +---------+-----------------+----------------------------------------------+
# | 6       | Server->Client  | A result code of kFPNoErr if authentication  |
# |         |                 |       was successful                         |
# +---------+-----------------+----------------------------------------------+
sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    die('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    my $nonce_limit = new Math::BigInt(1);
    $nonce_limit->blsft(128);

    die('Password callback MUST be a subroutine ref')
            unless ref($pw_cb) eq 'CODE';

    # Unlike with DHCAST128, since we don't know a variety of things yet,
    # we just send the username and the requested auth method first. We'll
    # start deriving values later.
    my %resp;
    # Sending message 1.
    my $rc;
    
    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                'AFPVersion'    => $AFPVersion,
                'UAM'           => UAMNAME,
                'UserName'      => $username);
        DEBUG('FPLoginExt() completed with result code ', $rc);
    }
    else {
        ($rc, %resp) = $session->FPLogin($AFPVersion, UAMNAME,
                pack('C/a*x![s]', $username));
        DEBUG('FPLogin() completed with result code ', $rc);
    }
    return $rc unless $rc == kFPAuthContinue;

    # Received message 2, parsing below.
    # Get the value for g, and the length value for assorted things (p, Ma,
    # Mb, Ra, Rb).
    my ($g_regular, $len, $extra) = unpack('Nna*', $resp{'UserAuthInfo'});

    # We need g to be a Math::BigInt object, so we can do large-value
    # exponentiation later (for deriving Ma and K) - even though it's
    # not a "big" number on its own.
    my $g = new Math::BigInt($g_regular);
    undef $g_regular;
    DEBUG('$g is ', $g->as_hex());
    DEBUG('$len is ', $len);

    # Pull p and Mb out of the data the server sent back, based on the length
    # value extracted above.
    my $template = 'H' . ($len * 2) . 'H' . ($len * 2);
    my ($p_text, $Mb_text) = unpack($template, $extra);
    undef $extra;
    my $p = new Math::BigInt('0x' . $p_text);
    undef $p_text;
    DEBUG('$p is ', $p->as_hex());
    my $Mb = new Math::BigInt('0x' . $Mb_text);
    undef $Mb_text;
    DEBUG('$Mb is ', $Mb->as_hex());

    # Get random bytes that constitute a large exponent for the random number
    # exchange we do.
    my $Ra_binary = Crypt::CBC->_get_random_bytes($len);
    my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
    undef $Ra_binary;
    DEBUG('$Ra is ', $Ra->as_hex());

    # Ma = g^Ra mod p <- This gives us the "random number" that we hand to
    # the server.
    my $Ma = $g->bmodpow($Ra, $p);
    undef $g;
    DEBUG('$Ma is ', $Ma->as_hex());
    my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), $len * 2));
    undef $Ma;

    # K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
    # and decrypt ciphertext for communicating with the server.
    my $K = $Mb->bmodpow($Ra, $p);
    undef $Mb;
    undef $Ra;
    undef $p;
    DEBUG('$K is ', $K->as_hex());
    my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), $len * 2));
    undef $K;
    my $K_hash = md5($K_binary);
    undef $K_binary;

    # Get our nonce, which we'll send to the server in the ciphertext.
    my $clientNonce_binary = Crypt::CBC->_get_random_bytes(16);
    my $clientNonce = new Math::BigInt('0x' .
            unpack('H*', $clientNonce_binary));
    DEBUG('$clientNonce is ', $clientNonce->as_hex());
    
    # Set up an encryption context with the key we derived, for encrypting
    # and decrypting stuff to talk to the server.
    my $ctx = new Crypt::CBC( { 'key'               => $K_hash,
                                'cipher'            => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                'padding'           => 'null',
                                'regenerate_key'    => 0,
                                'prepend_iv'        => 0,
                                'iv'                => C2SIV } );
    undef $K_hash;
    $$session{'cryptctx'} = $ctx;

    # Encrypt the random nonce value we fetched above, then assemble the
    # message to send to the server.
    #$ctx->set_initialization_vector(C2SIV);
    my $ciphertext = $ctx->encrypt($clientNonce_binary);
    undef $clientNonce_binary;
    my $message = $Ma_binary . $ciphertext;
    undef $Ma_binary;
    undef $ciphertext;
    DEBUG('$message is ', unpack('H*', $message));

    # Send the message to the server containing Ma (our "public key"), and
    # the encrypted nonce value.
    my $sresp = '';
    # Sending message 3.
    $rc = $session->FPLoginCont($resp{'ID'}, $message, \$sresp);
    undef $message;
    DEBUG('FPLoginCont() completed with result code ', $rc);
    return $rc unless $rc == kFPAuthContinue;

    # Decrypting message 4.
    # Decrypt the message from the server, and separate the (hopefully)
    # incremented nonce value from us, and the server's nonce value.
    $ctx->set_initialization_vector(S2CIV);
    my $decrypted = $ctx->decrypt($sresp->{'UserAuthInfo'});
    # HACK ALERT: seems decrypt() likes to drop the trailing null on me :|
    # this line should pad out to the appropriate length, which should
    # avoid this problem...
    $decrypted .= "\0" x (32 - length($decrypted));
    DEBUG('$decrypted is ', unpack('H*', $decrypted));
    my ($newClientNonce_text, $serverNonce_text) = unpack('H32H32', $decrypted);

    # Check the client nonce, and see if it really was incremented like we
    # expect it to have been.
    my $newClientNonce = new Math::BigInt('0x' . $newClientNonce_text);
    undef $newClientNonce_text;
    DEBUG('$newClientNonce is ', $newClientNonce->as_hex());
    $clientNonce->badd(1);
    $clientNonce = $clientNonce->bmod($nonce_limit);
    die('encryption error - nonce check failed')
            unless $clientNonce->bcmp($newClientNonce) == 0;
    undef $clientNonce;
    undef $newClientNonce;

    # Increment the nonce value the server sent to us, to be returned as part
    # of the encrypted response.
    my $serverNonce = new Math::BigInt('0x' . $serverNonce_text);
    undef $serverNonce_text;
    DEBUG('$serverNonce is ', $serverNonce->as_hex());
    $serverNonce->badd(1);
    $serverNonce = $serverNonce->bmod($nonce_limit);
    DEBUG('$serverNonce is ', $serverNonce->as_hex(), " after increment");
    my $newServerNonce_text = zeropad(substr($serverNonce->as_hex(), 2), 32);
    undef $serverNonce;

    # Assemble the final message to send back to the server with the
    # incremented server nonce, and the user's password, then encrypt the
    # message.
    my $authdata = pack('H32a256', $newServerNonce_text, &$pw_cb());
    undef $newServerNonce_text;
    $ctx->set_initialization_vector(C2SIV);
    $ciphertext = $ctx->encrypt($authdata);
    DEBUG('$ciphertext is ', unpack('H*', $ciphertext));

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($sresp->{'ID'}, $ciphertext);
    undef $ciphertext;
    DEBUG('FPLoginCont() completed with result code ', $rc);
    return $rc;
}

sub ChangePassword {
    my($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    die('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    my $nonce_limit = new Math::BigInt(1);
    $nonce_limit->blsft(128);

    my $resp = undef;

    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            kFPVerAtLeast)) {
        $username = '';
    }
    my $rc = $session->FPChangePassword(UAMNAME, $username, undef, \$resp);
    DEBUG('FPChangePassword() completed with result code ', $rc);
    return $rc unless $rc == kFPAuthContinue;

    # Get the value for g, and the length value for assorted things (p, Ma,
    # Mb, Ra, Rb).
    my ($ID, $g_regular, $len, $extra) = unpack('nNna*', $resp);

    # We need g to be a Math::BigInt object, so we can do large-value
    # exponentiation later (for deriving Ma and K) - even though it's
    # not a "big" number on its own.
    my $g = new Math::BigInt($g_regular);
    undef $g_regular;
    DEBUG('$g is ', $g->as_hex());
    DEBUG('$len is ', $len);

    # Pull p and Mb out of the data the server sent back, based on the length
    # value extracted above.
    my $template = 'H' . ($len * 2) . 'H' . ($len * 2);
    my ($p_text, $Mb_text) = unpack($template, $extra);
    undef $extra;
    my $p = new Math::BigInt('0x' . $p_text);
    undef $p_text;
    DEBUG('$p is ', $p->as_hex());
    my $Mb = new Math::BigInt('0x' . $Mb_text);
    undef $Mb_text;
    DEBUG('$Mb is ', $Mb->as_hex());

    # Get random bytes that constitute a large exponent for the random number
    # exchange we do.
    my $Ra_binary = Crypt::CBC->_get_random_bytes($len);
    my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
    undef $Ra_binary;
    DEBUG('$Ra is ', $Ra->as_hex());

    # Ma = g^Ra mod p <- This gives us the "random number" that we hand to
    # the server.
    my $Ma = $g->bmodpow($Ra, $p);
    undef $g;
    DEBUG('$Ma is ', $Ma->as_hex());
    my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), $len * 2));
    undef $Ma;

    # K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
    # and decrypt ciphertext for communicating with the server.
    my $K = $Mb->bmodpow($Ra, $p);
    undef $Mb;
    undef $Ra;
    undef $p;
    DEBUG('$K is ', $K->as_hex());
    my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), $len * 2));
    undef $K;

    # Get our nonce, which we'll send to the server in the ciphertext.
    my $clientNonce_binary = Crypt::CBC->_get_random_bytes(16);
    my $clientNonce = new Math::BigInt('0x' .
            unpack('H*', $clientNonce_binary));
    DEBUG('$clientNonce is ', $clientNonce->as_hex());
    
    # Set up an encryption context with the key we derived, for encrypting
    # and decrypting stuff to talk to the server. Note the setting of
    # literal_key to a false value, because in this method, we
    # actually want the MD5 hash of the key, not the key itself.
    my $ctx = new Crypt::CBC( { 'key'               => $K_binary,
                                'cipher'            => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                'padding'           => 'null',
                                'regenerate_key'    => 1,
                                'prepend_iv'        => 0,
                                'iv'                => C2SIV } );
    undef $K_binary;

    # Encrypt the random nonce value we fetched above, then assemble the
    # message to send to the server.
    #$ctx->set_initialization_vector(C2SIV);
    my $ciphertext = $ctx->encrypt($clientNonce_binary);
    undef $clientNonce_binary;
    my $message = pack('na[' . $len . ']a*', $ID, $Ma_binary, $ciphertext);
    undef $Ma_binary;
    undef $ciphertext;
    DEBUG('$message is ', unpack('H*', $message));

    # Send the message to the server containing Ma (our "public key"), and
    # the encrypted nonce value.
    my $sresp = '';
    $rc = $session->FPChangePassword(UAMNAME, $username, $message, \$sresp);
    DEBUG('FPChangePassword() completed with result code ', $rc);
    return $rc unless $rc == kFPAuthContinue;
    undef $message;

    # Unpack the server response for our perusal.
    ($ID, $message) = unpack('na*', $sresp);

    # Decrypt the message from the server, and separate the (hopefully)
    # incremented nonce value from us, and the server's nonce value.
    $ctx->set_initialization_vector(S2CIV);
    my $decrypted = $ctx->decrypt($message);
    # HACK ALERT: seems decrypt() likes to drop the trailing null on me :|
    # this line should pad out to the appropriate length, which should
    # avoid this problem...
    $decrypted .= "\0" x (32 - length($decrypted));
    undef $message;
    DEBUG('$decrypted is ', unpack('H*', $decrypted));
    my ($newClientNonce_text, $serverNonce_text) = unpack('H32H32', $decrypted);

    # Check the client nonce, and see if it really was incremented like we
    # expect it to have been.
    my $newClientNonce = new Math::BigInt('0x' . $newClientNonce_text);
    undef $newClientNonce_text;
    DEBUG('$newClientNonce is ', $newClientNonce->as_hex());
    $clientNonce->badd(1);
    $clientNonce = $clientNonce->bmod($nonce_limit);
    die('encryption error - nonce check failed')
            unless $clientNonce->bcmp($newClientNonce) == 0;
    undef $clientNonce;
    undef $newClientNonce;

    # Increment the nonce value the server sent to us, to be returned as part
    # of the encrypted response.
    my $serverNonce = new Math::BigInt('0x' . $serverNonce_text);
    undef $serverNonce_text;
    DEBUG('$serverNonce is ', $serverNonce->as_hex());
    $serverNonce->badd(1);
    $serverNonce = $serverNonce->bmod($nonce_limit);
    DEBUG('$serverNonce is ', $serverNonce->as_hex(), " after increment");
    my $newServerNonce_text = zeropad(substr($serverNonce->as_hex(), 2), 32);
    undef $serverNonce;

    # Assemble the final message to send back to the server with the
    # incremented server nonce, the user's current password, and the
    # desired new password, then encrypt the message.
    my $authdata = pack('H32a256a256', $newServerNonce_text, $newPassword,
            $oldPassword);
    undef $newServerNonce_text;
    $ctx->set_initialization_vector(C2SIV);
    $ciphertext = $ctx->encrypt($authdata);
    DEBUG('$ciphertext is ', unpack('H*', $ciphertext));

    $message = pack('na*', $ID, $ciphertext);
    undef $ciphertext;

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPChangePassword(UAMNAME, $username, $message);
    undef $message;
    DEBUG('FPChangePassword() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
