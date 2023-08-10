# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::Reconnect;

use Net::AFP::Parsers;
use Net::AFP::Result;
use Net::AFP::TokenTypes;
use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'Recon1';

# Crypt::Mode::CBC doesn't like if I make these Readonly.
my $C2SIV = 'WOMDMOAB';
my $S2CIV = 'WOMDMOAB';

Readonly my $nonce_len => 16;

# CryptX modules for crypto-related functionality.
use Crypt::Mode::CBC;
use Crypt::PRNG qw(random_bytes);
use Crypt::Digest::MD5 qw(md5);
use Crypt::Mac::HMAC qw(hmac);

sub GetCred {
    my($session) = @_;

    unless (exists $session->{SessionKey}) {
        print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
        return undef;
    }

    my $t1 = time() - globalTimeOffset;
    my $ctx = Crypt::Mode::CBC->new('CAST5', 0);
    my $ciphertext = $ctx->encrypt(pack('L>', $t1), $session->{SessionKey},
            $C2SIV);
    my $resp;
    my $rc = $session->FPGetSessionToken($kRecon1Login,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc if $rc != $kFPNoErr;

    my $token = $ctx->decrypt($resp, $session->{SessionKey}, $S2CIV);
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
    my $ctx = Crypt::Mode::CBC->new('CAST5', 0);
    my $ciphertext = $ctx->encrypt(pack('L>a*', $session->{t1}, $session->{cred}),
            $session->{SessionKey}, $C2SIV);
    my $resp;
    my $rc = $session->FPGetSessionToken($kRecon1RefreshToken,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc if $rc != $kFPNoErr;

    my $newkey = md5($session->{SessionKey} . $session->{cred});
    my $token = $ctx->decrypt($resp, $newkey, $C2SIV);
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
    my $ctx = Crypt::Mode::CBC->new('CAST5', 0);
    my $clientNonce = random_bytes($nonce_len);
    my $ciphertext = $ctx->encrypt($clientNonce, $k, $C2SIV);
    my $sig = pack('a[16]L>L>a[' . $nonce_len . ']a*', $hashval, $n, $t2,
                   $ciphertext, $session->{cred});
    $sig = hmac(q{MD5}, $session->{s}, $sig);
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
    my $decrypted = $ctx->decrypt($resp{UserAuthInfo}, $k, $S2CIV);
    my($serverNonce, $clientNonce_hash) =
        unpack('a[' . $nonce_len . ']a[16]', $decrypted);
    return $kFPUserNotAuth if md5($clientNonce) ne $clientNonce_hash;
    undef $decrypted;

    # this is step 3
    $ciphertext = $ctx->encrypt(md5($serverNonce), $k, $C2SIV);
    $session->FPLoginCont($resp{ID}, $ciphertext);
    undef $ciphertext;

    # this is step 4
    return $rc if $rc != $kFPNoErr;

    # if we've gotten to this point, we make a new session key based on the
    # hash of the client and server nonces
    $session->{sessionKey} = md5($clientNonce . $serverNonce);

    # this is step 5
    $ciphertext = $ctx->encrypt(pack('L>a*', $session->{t1}, $session->{cred}),
            $session->{SessionKey}, $C2SIV);
    my $resp;
    $rc = $session->FPGetSessionToken($kRecon1ReconnectLogin,
        $ciphertext, q{}, \$resp);
    $session->{logger}->debug('FPGetSessionToken() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
