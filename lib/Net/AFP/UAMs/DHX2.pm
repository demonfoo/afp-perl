# This package fairly correctly implements the DHX2 User Authentication Method
# for AFP sessions. It requires CryptX for various crypto-related actions.

# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::DHX2;

use Modern::Perl '2021';
use diagnostics;
use integer;
use Carp;
use Data::Dumper;

use Readonly;
Readonly my $UAMNAME => 'DHX2';

# Crypt::Mode::CBC doesn't like if I make these Readonly.
my $C2SIV = 'LWallace';
my $S2CIV = 'CJalbert';

Readonly my $nonce_len => 16;
Readonly my $pw_len    => 256;

# CryptX modules for crypto-related functionality.
use Crypt::Mode::CBC;
use Crypt::PRNG qw(random_bytes);
use Crypt::Digest::MD5 qw(md5);
use Crypt::PK::DH;
use Crypt::Misc qw(increment_octets_be);
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 200);

##no critic qw(RequireArgUnpacking)
sub zeropad {
    if (length($_[0]) > $_[1]) {
        return substr $_[0], length($_[0]) - $_[1], $_[1];
    }
    else {
        return "\0" x ($_[1] - length $_[0]) . $_[0];
    }
}

# since these parts are the same between authentication and password changing,
# let's not write the whole thing twice, eh?
sub auth_common1 {
    my($session, $message, $store_sesskey) = @_;

    # Get the value for g, and the length value for assorted things (p, Ma,
    # Mb, Ra, Rb).
    my ($g, $len, $p, $Mb) = unpack q{L>S>X[s]S>/aa*}, $message;

    $session->{logger}->debug(sub { sprintf q{g is %d}, $g });
    $session->{logger}->debug(sub { sprintf q{len is %d}, $len });

    # Pull p and Mb out of the data the server sent back, based on the length
    # value extracted above.
    $p = '0x' . unpack q{H*}, $p;
    $session->{logger}->debug(sub { sprintf q{p is %s}, $p });

    my $dh = Crypt::PK::DH->new();
    $dh->generate_key({p => $p, g => $g});

    my $K = $dh->shared_secret(Crypt::PK::DH->new()->import_key_raw($Mb, 'public',
      {p => $p, g => $g}));
    undef $Mb;
    $session->{logger}->debug(sub { sprintf q{K is 0x%s}, unpack q{H*}, $K });

    # Get our nonce, which we'll send to the server in the ciphertext.
    my $clientNonce = zeropad(random_bytes($nonce_len), $nonce_len);
    $session->{logger}->debug(sub { sprintf q{clientNonce is %s},
      unpack q{H*}, $clientNonce });

    # Set up an encryption context with the key we derived, for encrypting
    # and decrypting stuff to talk to the server.
    my $key = md5(zeropad($K, $len));
    if ($store_sesskey) {
        $session->{SessionKey} = $key;
    }
    undef $K;
    my $ctx = Crypt::Mode::CBC->new('CAST5', 0);

    # Encrypt the random nonce value we fetched above, then assemble the
    # message to send to the server.
    my $ciphertext = $ctx->encrypt(zeropad($clientNonce, $nonce_len),
            $key, $C2SIV);
    my $Ma = $dh->export_key_raw('public');
    # Sometimes the result is an extra (zero) byte long; strip that off.
    if (length($Ma) > $len) {
        $Ma = substr $Ma, length($Ma) - $len, $len;
    }

    $message = pack qq{a[${len}]a[${nonce_len}]}, $Ma, $ciphertext;

    return($message, $clientNonce, $ctx, $key);
}

sub auth_common2 {
    my($session, $key, $message, $clientNonce, $ctx) = @_;

    # Decrypt the message from the server, and separate the (hopefully)
    # incremented nonce value from us, and the server's nonce value.
    my $decrypted = $ctx->decrypt($message, $key, $S2CIV);
    $session->{logger}->debug(sub { sprintf q{decrypted is 0x%s},
      unpack q{H*}, $decrypted });

    # Check the client nonce, and see if it really was incremented like we
    # expect it to have been.
    # if all bits are 1, this will throw a fatal error.
    my $newClientNonce = unpack sprintf(q{a[%d]}, $nonce_len), $decrypted;
    $session->{logger}->debug(sub { sprintf q{newClientNonce is %s},
      unpack q{H*}, $newClientNonce });
    if (increment_octets_be($clientNonce) ne $newClientNonce) {
        # HACK: This is a netatalk bug. If the client nonce is less than the
        # full nonce length, it doesn't check to make sure the value fills
        # the entire target buffer, so garbage bytes get left behind after it,
        # gumming up the works. It's fixed in their current git.
        # https://github.com/Netatalk/netatalk/issues/1456
        # In the meantime, I'll just... work around it.
        increment_octets_be($clientNonce) =~ m{^\x00+(.*)$};
        my $altClientNonce = $1;

        $newClientNonce = unpack sprintf(q{a[%d]}, length $altClientNonce), $decrypted;

        if ($altClientNonce ne $newClientNonce) {
            croak('encryption error - nonce check failed; ' .
              $clientNonce->as_hex() . ' != ' . $newClientNonce->as_hex());
        }
    }
    undef $clientNonce;
    undef $newClientNonce;

    # Increment the nonce value the server sent to us, to be returned as part
    # of the encrypted response.
    my $serverNonce = unpack sprintf(q{x[%d]a[%d]}, $nonce_len, $nonce_len),
      $decrypted;
    undef $decrypted;
    $session->{logger}->debug(sub { sprintf q{serverNonce is %s},
      unpack q{H*}, $serverNonce });
    $serverNonce = increment_octets_be($serverNonce);;
    $session->{logger}->debug(sub { sprintf q{serverNonce is %s after increment},
      $serverNonce->as_hex() });

    return($serverNonce);
}

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
# | 6       | Server->Client  | A result code of $kFPNoErr if authentication |
# |         |                 |       was successful                         |
# +---------+-----------------+----------------------------------------------+
sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa('Net::AFP')) {
        croak('Object MUST be of type Net::AFP!');
    }

    if (ref($pw_cb) ne 'CODE') {
        croak('Password callback MUST be a subroutine ref');
    }

    # Unlike with DHCAST128, since we don't know a variety of things yet,
    # we just send the username and the requested auth method first. We'll
    # start deriving values later.
    my %resp;
    # Sending message 1.
    my $rc;

    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                AFPVersion => $AFPVersion,
                UAM        => $UAMNAME,
                UserName   => $username);
        $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);
    }
    else {
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME,
                pack q{C/a*x![s]}, $username);
        $session->{logger}->debug('FPLogin() completed with result code ', $rc);
    }
    return $rc if $rc != $kFPAuthContinue;

    # Received message 2, parsing below.
    my($message, $clientNonce, $ctx, $key) = auth_common1($session,
      $resp{UserAuthInfo}, 1);

    $session->{logger}->debug(sub { sprintf q{message is 0x%s},
      unpack q{H*}, $message });

    # Send the message to the server containing Ma (our "public key"), and
    # the encrypted nonce value.
    my $sresp = q{};
    # Sending message 3.
    $rc = $session->FPLoginCont($resp{ID}, $message, \$sresp);
    undef $message;
    $session->{logger}->debug(sub { sprintf q{FPLoginCont() completed with } .
      q{result code %d}, $rc });
    return $rc if $rc != $kFPAuthContinue;

    # Decrypting message 4.
    my($serverNonce) = auth_common2($session, $key, $sresp->{UserAuthInfo}, $clientNonce, $ctx);

    # Assemble the final message to send back to the server with the
    # incremented server nonce, and the user's password, then encrypt the
    # message.
    my $authdata = pack qq{a[${nonce_len}]a[${pw_len}]},
	                zeropad($serverNonce, $nonce_len), &{$pw_cb}();
    undef $serverNonce;
    my $ciphertext = $ctx->encrypt($authdata, $key, $C2SIV);
    $session->{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($sresp->{ID}, $ciphertext);
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

    my $resp = undef;

    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            $kFPVerAtLeast)) {
        $username = q{};
    }
    my $rc = $session->FPChangePassword($UAMNAME, $username, q{}, \$resp);
    $session->{logger}->debug('FPChangePassword() completed with result code ', $rc);
    return $rc if $rc != $kFPAuthContinue;

    my ($ID, $body) = unpack q{S>a*}, $resp;
    my($message, $clientNonce, $ctx, $key) = auth_common1($session, $body, 0);
    undef $body;

    $message = pack q{na*}, $ID, $message;
    $session->{logger}->debug(sub { sprintf q{message is 0x%s},
      unpack q{H*}, $message });

    # Send the message to the server containing Ma (our "public key"), and
    # the encrypted nonce value.
    my $sresp = q{};
    $rc = $session->FPChangePassword($UAMNAME, $username, $message, \$sresp);
    undef $message;
    $session->{logger}->debug(sub { sprintf q{FPChangePassword() completed } .
      q{with result code %d}, $rc });
    return $rc if $rc != $kFPAuthContinue;

    # Unpack the server response for our perusal.
    ($ID, $message) = unpack q{na*}, $sresp;

    my($serverNonce) = auth_common2($session, $key, $message, $clientNonce, $ctx);

    # Assemble the final message to send back to the server with the
    # incremented server nonce, the user's current password, and the
    # desired new password, then encrypt the message.
    my $authdata = pack qq{a[${nonce_len}]a[${pw_len}]a[${pw_len}]},
	                zeropad($serverNonce, $nonce_len),
	                $newPassword, $oldPassword;
    undef $serverNonce;
    my $ciphertext = $ctx->encrypt($authdata, $key, $C2SIV);
    $session->{logger}->debug(sub { sprintf q{ciphertext is 0x%s},
      unpack q{H*}, $ciphertext });

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPChangePassword($UAMNAME, $username, pack q{na*}, $ID, $ciphertext);
    undef $ciphertext;
    $session->{logger}->debug('FPChangePassword() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
