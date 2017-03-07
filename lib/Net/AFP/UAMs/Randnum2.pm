# This package implements the 2-Way Random Number Exchange User Authentication
# Method for AFP. It uses Crypt::DES for the actual DES encryption used
# as part of the authentication process.

# This UAM was added as of AFP 2.1.

package Net::AFP::UAMs::Randnum2;

use strict;
use warnings;
use diagnostics;
use integer;

use Readonly;
Readonly my $UAMNAME => '2-Way Randnum exchange';

use Crypt::DES;
use Crypt::CBC;
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl qw(:easy);

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 60);

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    die('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    die('Password callback MUST be a subroutine ref')
            unless ref($pw_cb) eq 'CODE';

    # Pack just the username into a Pascal-style string, and send that to
    # the server.
    my %resp;
    my $rc;
    
    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc, %resp) = $session->FPLoginExt(
                AFPVersion  => $AFPVersion,
                UAM         => $UAMNAME,
                UserName    => $username);
        DEBUG('FPLoginExt() completed with result code ', $rc);
    }
    else {
        my $authinfo = pack('C/a*', $username);
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $authinfo);
        DEBUG('FPLogin() completed with result code ', $rc);
    }

    return $rc unless $rc == $kFPAuthContinue;

    # The server will send us a random 8-byte number; take that, and encrypt
    # it with the password the user gave us.
    my($randnum) = unpack('a8', $resp{'UserAuthInfo'});
    DEBUG('$randnum is 0x', unpack('H*', $randnum));
    # Explode the password out into a bit string, and rotate the leftmost bit
    # to the end of the bit vector.
    my $bin_key = unpack('B*', pack('a8', &$pw_cb()));
    $bin_key =~ s/^([01])(.*)$/$2$1/;
    # Pack the rotated bitstring back into binary form for use as the DES key.
    my $key = pack('B*', $bin_key);
    undef $bin_key;
    my $deshash = new Crypt::DES($key);
    undef $key;
    my $crypted = $deshash->encrypt($randnum);
    undef $randnum;
    DEBUG('$crypted is 0x', unpack('H*', $crypted));

    # Get some random bytes to send to the server. It will encrypt its copy
    # of the password, and send it back to us, to verify that it too has a
    # copy of the password, and it's not just phishing for hashes.
    my $my_randnum = Crypt::CBC->_get_random_bytes(8);
    DEBUG('$my_randnum is 0x', unpack('H*', $my_randnum));

    # Send the response back to the server. If the server doesn't think we're
    # okay, then return the result code right away.
    my $sresp = undef;
    $rc = $session->FPLoginCont($resp{'ID'}, $crypted . $my_randnum, \$sresp);
    undef $crypted;
    DEBUG('FPLoginCont() completed with result code ', $rc);
    return $rc unless $rc == $kFPNoErr;
    
    # Now, verify the server's crypted copy of the password to ensure that
    # they really have it.
    my($srv_hash) = unpack('a8', $sresp->{'UserAuthInfo'});
    DEBUG('$srv_hash is 0x', unpack('H*', $srv_hash));
    my $recrypted = $deshash->encrypt($my_randnum);
    undef $my_randnum;
    DEBUG('$recrypted is 0x', unpack('H*', $recrypted));
    # Maybe a different result code is in order? Not sure...
    return $kFPUserNotAuth unless $srv_hash eq $recrypted;
    undef $srv_hash;
    undef $recrypted;

    # If we've reached this point, all went well, so return success.
    return $kFPNoErr;
}

# This UAM does not implement password changing; Randnum.pm's ChangePassword()
# function should be used instead.

1;
# vim: ts=4
