# This package implements the 2-Way Random Number Exchange User Authentication
# Method for AFP. It uses Crypt::Cipher::DES for the actual DES encryption used
# as part of the authentication process.

# This UAM was added as of AFP 2.1.

package Net::AFP::UAMs::Randnum2;

use Modern::Perl q{2021};
use diagnostics;
use integer;
use Carp;
use Crypt::PRNG qw(random_bytes);

use Readonly;
Readonly my $UAMNAME => q{2-Way Randnum exchange};

use Crypt::Cipher::DES;
use Net::AFP::Result;
use Net::AFP::Versions;
use Log::Log4perl;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 60);

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
        $session->{logger}->debug(q{FPLoginExt() completed with result code },
          $rc);
    }
    else {
        my $authinfo = pack q{C/a*}, $username;
        ($rc, %resp) = $session->FPLogin($AFPVersion, $UAMNAME, $authinfo);
        $session->{logger}->debug(q{FPLogin() completed with result code },
          $rc);
    }

    if ($rc != $kFPAuthContinue) {
        return $rc;
    }

    # The server will send us a random 8-byte number; take that, and encrypt
    # it with the password the user gave us.
    my($randnum) = unpack q{a[8]}, $resp{UserAuthInfo};
    $session->{logger}->debug(sub { sprintf q{randnum is 0x%s},
      unpack q{H*}, $randnum });
    # Explode the password out into a bit string, and rotate the leftmost bit
    # to the end of the bit vector.
    my $bin_key = unpack q{B*}, pack q{a[8]}, &{$pw_cb}();
    $bin_key =~ s/^([01])(.*)$/$2$1/sm;
    # Pack the rotated bitstring back into binary form for use as the DES key.
    my $key = pack q{B*}, $bin_key;
    undef $bin_key;
    my $deshash = Crypt::Cipher::DES->new($key);
    undef $key;
    my $crypted = $deshash->encrypt($randnum);
    undef $randnum;
    $session->{logger}->debug(sub { sprintf q{crypted is 0x%s},
      unpack q{H*}, $crypted });

    # Get some random bytes to send to the server. It will encrypt its copy
    # of the password, and send it back to us, to verify that it too has a
    # copy of the password, and it's not just phishing for hashes.
    my $my_randnum = random_bytes(8);
    $session->{logger}->debug(sub { sprintf q{my_randnum is 0x%s},
      unpack q{H*}, $my_randnum });

    # Send the response back to the server. If the server doesn't think we're
    # okay, then return the result code right away.
    my $sresp = undef;
    $rc = $session->FPLoginCont($resp{ID}, $crypted . $my_randnum, \$sresp);
    undef $crypted;
    $session->{logger}->debug(sub { sprintf q{FPLoginCont() completed with } .
      q{result code %d}, $rc });
    if ($rc != $kFPNoErr) {
        return $rc;
    }

    # Now, verify the server's crypted copy of the password to ensure that
    # they really have it.
    my($srv_hash) = unpack q{a[8]}, $sresp->{UserAuthInfo};
    $session->{logger}->debug(sub { sprintf q{srv_hash is 0x%s},
      unpack q{H*}, $srv_hash });
    my $recrypted = $deshash->encrypt($my_randnum);
    undef $my_randnum;
    $session->{logger}->debug(sub { sprintf q{recrypted is 0x%s},
      unpack q{H*}, $recrypted });
    # Maybe a different result code is in order? Not sure...
    if ($srv_hash ne $recrypted) {
        return $kFPUserNotAuth;
    }
    undef $srv_hash;
    undef $recrypted;

    # If we've reached this point, all went well, so return success.
    return $kFPNoErr;
}

# This UAM does not implement password changing; Randnum.pm's ChangePassword()
# function should be used instead.

1;
# vim: ts=4
