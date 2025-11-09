# This package implements the Random Number Exchange User Authentication
# Method for AFP. It uses Crypt::Cipher::DES for the actual DES encryption used
# as part of the authentication process.
# This UAM is considered deprecated by Apple, and OS X no longer supports
# its use. This is for legacy compatibility only. (Does that apply to
# 2-way randnum as well?)

package Net::AFP::UAMs::Randnum;

use Modern::Perl q{2021};
use diagnostics;
use integer;
use Carp;

use Readonly;
Readonly my $UAMNAME => q{Randnum exchange};

use Crypt::Cipher::DES;
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 50);

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa(q{Net::AFP})) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    if (ref($pw_cb) ne q{CODE}) {
        croak(q{Password callback MUST be a subroutine ref});
    }

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
        $session->{logger}->debug(sub { sprintf q{FPLoginExt() completed with } .
          q{result code %d}, $rc });
    }
    else {
        my $authinfo = pack q{C/a*}, $username;
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $authinfo);
        $session->{logger}->debug(sub { sprintf q{FPLogin() completed with } .
          q{result code %d}, $rc });
    }

    if ($rc != $kFPAuthContinue) {
        return $rc;
    }

    # The server will send us a random 8-byte number; take that, and encrypt
    # it with the password the user gave us.
    my ($randnum) = unpack q{a[8]}, $resp{UserAuthInfo};
    $session->{logger}->debug(sub { sprintf q{randnum is 0x%s},
      unpack q{H*}, $randnum });
    my $deshash = Crypt::Cipher::DES->new(pack q{a[8]}, &{$pw_cb}());
    my $crypted = $deshash->encrypt($randnum);
    undef $randnum;
    $session->{logger}->debug(sub { sprintf q{crypted is 0x%s},
      unpack q{H*}, $crypted });

    # Send the response back to the server, and hope we did this right.
    $rc = $session->FPLoginCont($resp{ID}, $crypted);
    undef $crypted;
    $session->{logger}->debug(sub { sprintf q{FPLoginCont() completed with } .
      q{result code %d}, $rc});
    return $rc;
}

sub ChangePassword {
    my ($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    if (not ref $session or not $session->isa(q{Net::AFP})) {
        croak(q{Object MUST be of type Net::AFP!});
    }

    # Establish encryption contexts for each of the supplied passwords. Then
    # pack the old password encrypted with the new one, and the new password
    # encrypted with the old one, as directed.
    my $oldcrypt = Crypt::Cipher::DES->new(pack q{a[8]}, $oldPassword);
    my $newcrypt = Crypt::Cipher::DES->new(pack q{a[8]}, $newPassword);
    my $message = pack q{a[8]a[8]}, $newcrypt->encrypt($oldPassword),
            $oldcrypt->encrypt($newPassword);
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
    $session->{logger}->debug(sub { sprintf q{FPChangePassword() completed } .
      q{with result code %d}, $rc });
    return $rc;
}

1;
# vim: ts=4
