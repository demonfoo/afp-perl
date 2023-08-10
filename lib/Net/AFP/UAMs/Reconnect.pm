# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::Reconnect;

use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::AFP::TokenTypes;
use Digest::MD5 qw(md5);
use Digest::HMAC_MD5 qw(hmac_md5);
use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'Recon1';

Readonly my $C2SIV => 'WOMDMOAB';
Readonly my $S2CIV => 'WOMDMOAB';

Readonly my $nonce_len => 16;

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
croak("No CAST5 implementation was available?")
        unless $has_Crypt__CAST5 || $has_Crypt__CAST5_PP;

# Provides the cipher-block chaining layer over the encryption algorithm.
use Crypt::CBC;

sub GetCred {
    my($session) = @_;

    unless (exists $session->{SessionKey}) {
        print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
        return undef;
    }

    my $t1 = time() - globalTimeOffset;
    my $ctx = Crypt::CBC->new({ key     => $session->{SessionKey},
                                cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                padding => 'none',
                                pbkdf   => 'none',
                                header  => 'none',
                                iv      => $C2SIV });
    my $ciphertext = $ctx->encrypt(pack('L>', $t1));
    my $resp;
    my $rc = $session->FPGetSessionToken($kRecon1Login,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc if $rc != $kFPNoErr;

    $ctx->set_initialization_vector($S2CIV);
    my $token = $ctx->decrypt($resp);
    print "decrypted token data is: ", unpack('H*', $token), "\n";
    @{$session}{qw[cred s m exp sessionInfo]} =
        unpack('a[' . length($token) - 24 .  ']a[8]L>L>a[8]', $token);
    ${$session}{t1} = $t1;

    return 0;
}

sub RefreshCred {
    my($session) = @_;

    unless (exists $session->{SessionKey} and exists $session->{cred}) {
        print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
        return undef;
    }
    my $ctx = Crypt::CBC->new({ key     => $session->{SessionKey},
                                cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                padding => 'none',
                                pbkdf   => 'none',
                                header  => 'none',
                                iv      => $C2SIV });

    my $ciphertext = $ctx->encrypt(pack('L>a*', $session->{t1}, $session->{cred}));
    my $resp;
    my $rc = $session->FPGetSessionToken($kRecon1RefreshToken,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc if $rc != $kFPNoErr;

    my $newctx = Crypt::CBC->new({ key     => md5($session->{SessionKey} . $session->{cred}),
                                   cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                   padding => 'none',
                                   pbkdf   => 'none',
                                   header  => 'none',
                                   iv      => $C2SIV });

    $newctx->set_initialization_vector($S2CIV);
    my $token = $newctx->decrypt($resp);
    @{$session}{qw[cred s m exp sessionInfo]} =
        unpack('a[' . length($token) - 24 .  ']a[8]L>L>a[8]', $token);
    return 0;
}

sub Reconnect {
    my($session, $AFPVersion, $username, $VolID) = @_;

    # We decide how many iterations to do, based on what the server says the
    # max iteration count is.
    my $n = int(rand($session->{m})) + 1;
    # We want the timestamp for _now_.
    my $t2 = time() - globalTimeOffset;
    my $hashval = $session->{s};
    my $k;
    # Compute the given number of iterations of MD5; the prior iteration
    # is used as the key for encrypting the nonce.
    for (my $i = 0; $i < $n; $i++) {
        $k = $hashval;
        $hashval = md5($hashval);
    }
    my $ctx = Crypt::CBC->new({ key     => $k,
                                cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                padding => 'none',
                                pbkdf   => 'none',
                                header  => 'none',
                                iv      => $C2SIV });

    my $clientNonce = random_bytes($nonce_len);
    my $ciphertext = $ctx->encrypt($clientNonce);
    my $sig = pack('a[16]L>L>a[' . $nonce_len . ']a*', $hashval, $n, $t2,
                   $ciphertext, $session->{cred});
    $sig = hmac_md5($sig, $session->{s});
    my $authinfo = pack('a[16]a[16]L>L>a*a*', $sig, $hashval, $n, $t2,
                        $ciphertext, $session->{cred});
    undef $ciphertext;

    # this is step 1
    my ($rc, %resp) = $session->FPLoginExt(
            AFPVersion   => $AFPVersion,
            UAM          => $UAMNAME,
            UserName     => $username,
            UserAuthInfo => $authinfo );

    $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);

    return $rc unless $rc = $kFPAuthContinue;

    # this is step 2
    $ctx->set_initialization_vector($S2CIV);
    my $decrypted = $ctx->decrypt($resp{UserAuthInfo});
    my($serverNonce, $clientNonce_hash) =
        unpack('a[' . $nonce_len . ']a[16]', $decrypted);
    return $kFPUserNotAuth if md5($clientNonce) ne $clientNonce_hash;
    undef $decrypted;

    # this is step 3
    $ctx->set_initialization_vector($C2SIV);
    $ciphertext = $ctx->encrypt(md5($serverNonce));
    $session->FPLoginCont($resp{ID}, $ciphertext);
    undef $ciphertext;

    # this is step 4
    return $rc if $rc != $kFPNoErr;

    # if we've gotten to this point, we make a new session key based on the
    # hash of the client and server nonces
    $session->{sessionKey} = md5($clientNonce . $serverNonce);

    my $newctx = Crypt::CBC->new({ key     => $session->{sessionKey},
                                   cipher  => $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
                                   padding => 'none',
                                   pbkdf   => 'none',
                                   header  => 'none',
                                   iv      => $C2SIV });

    # this is step 5
    $ciphertext = $newctx->encrypt(pack('L>a*', $session->{t1}, $session->{cred}));
    my $resp;
    $rc = $session->FPGetSessionToken($kRecon1ReconnectLogin,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
