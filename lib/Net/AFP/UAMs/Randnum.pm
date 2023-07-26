# This package implements the Random Number Exchange User Authentication
# Method for AFP. It uses Crypt::DES for the actual DES encryption used
# as part of the authentication process.
# This UAM is considered deprecated by Apple, and OS X no longer supports
# its use. This is for legacy compatibility only. (Does that apply to
# 2-way randnum as well?)

package Net::AFP::UAMs::Randnum;

use Modern::Perl '2021';
use diagnostics;
use integer;
use Carp;

use Readonly;
Readonly my $UAMNAME => 'Randnum exchange';

use Crypt::DES;
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl qw(:easy);

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 50);

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    croak('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    croak('Password callback MUST be a subroutine ref')
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
    my ($randnum) = unpack('a8', $resp{UserAuthInfo});
    DEBUG('$randnum is 0x', unpack('H*', $randnum));
    my $deshash = Crypt::DES->new(pack('a8', &{$pw_cb}()));
    my $crypted = $deshash->encrypt($randnum);
    undef $randnum;
    DEBUG('$crypted is 0x', unpack('H*', $crypted));

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($resp{'ID'}, $crypted);
    undef $crypted;
    DEBUG('FPLoginCont() completed with result code ', $rc);
    return $rc;
}

sub ChangePassword {
    my ($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    croak('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    # Establish encryption contexts for each of the supplied passwords. Then
    # pack the old password encrypted with the new one, and the new password
    # encrypted with the old one, as directed.
    my $oldcrypt = Crypt::DES->new(pack('a8', $oldPassword));
    my $newcrypt = Crypt::DES->new(pack('a8', $newPassword));
    my $message = pack('a8a8', $newcrypt->encrypt($oldPassword),
            $oldcrypt->encrypt($newPassword));
    undef $oldcrypt;
    undef $newcrypt;

    # Send the message to the server, and pass the return code directly
    # back to the caller.
    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            $kFPVerAtLeast)) {
        $username = q{};
    }
    my $rc = $session->FPChangePassword($UAMNAME, $username, $message);
    undef $message;
    DEBUG('FPChangePassword() completed with result code ', $rc);
    return $rc;
}

1;
# vim: ts=4
