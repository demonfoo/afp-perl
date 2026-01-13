#!/usr/bin/env perl

# test the DHCAST128 UAM.

use strict;
use warnings;
use English qw(-no_match_vars);
BEGIN {
    $OUTPUT_AUTOFLUSH = 1;
    $WARNING          = 1;
}
use Test::More;
use Log::Log4perl qw(:easy);
use Net::AFP::Result;
use Crypt::PRNG qw(random_bytes);
use Crypt::Mode::CBC;
use Crypt::PK::DH;
use Crypt::Misc qw(increment_octets_be);

# just do this so it doesn't whine
Log::Log4perl->easy_init($ERROR);

# we need a mostly-empty "Net::AFP::UAMs" that pretends to register
# a UAM when it loads, so that we can call its methods.
{
    package Net::AFP::UAMs;

    sub RegisterUAM {
        # do nothing, this is just a placeholder
    }

    # borrowed from the real Net::AFP::UAMs
    sub zeropad {
        if (length($_[0]) > $_[1]) {
            return substr $_[0], length($_[0]) - $_[1], $_[1];
        }
        else {
            return(qq{\0} x ($_[1] - length $_[0]) . $_[0]);
        }
    }
}

my $server_password;
# just pretend to be enough of Net::AFP to test this UAM
{
    package Net::AFP;

    # create a mostly empty object, but with some values populated that
    # we need to have; some others get added for state tracking.
    sub new {
        my $obj = {};
        bless $obj, $_[0];
        %{$obj} = (
            # gotta provide this for all the stuff that uses it.
            logger        => Log::Log4perl->get_logger(),
            # right out of the UAM docs and module.
            p             => q{0xba2873dfb06057d43f2024744ceee75b},
            g             => q{0x07},
            # initialization vectors
            C2SIV         => q{LWallace},
            S2CIV         => q{CJalbert},
            # length of key values, p, etc.
            len           => 16,
            # length of nonces
            nonce_len     => 16,
            # max password length this UAM can handle
            pw_len        => 64,
            # the size of the "signature" (which is empty anyway, but...)
            signature_len => 16,
        );
        return $obj;
    }

    # this is the first part of the DHX/DHCAST128 conversation, broken
    # out into its own subroutine, so both the authentication and
    # password changing paths can use the same implementation.
    sub dhx_part1 {
        my($obj, $Ma, $pfx) = @_;
        $pfx ||= q{};
        
        if (length($Ma) != ${$obj}{len}) {
            return $Net::AFP::Result::kFPParamErr;
        }
        printf qq{client pubkey is %s\n}, unpack q{H*}, $Ma;
        (my $dh = Crypt::PK::DH->new())
          ->generate_key({ p => ${$obj}{p}, g => ${$obj}{g}});
        my $Mb = Net::AFP::UAMs::zeropad($dh->export_key_raw(q{public}),
          ${$obj}{len});
        printf qq{server pubkey is %s\n}, unpack q{H*}, $Mb;
        ${$obj}{$pfx . q{K}} = Net::AFP::UAMs::zeropad(
          $dh->shared_secret(Crypt::PK::DH->new()
          ->import_key_raw($Ma, q{public},
          { p => ${$obj}{p}, g => ${$obj}{g}})), ${$obj}{len});
        printf qq{key is %s\n}, unpack q{H*}, ${$obj}{$pfx . q{K}};
        ${$obj}{$pfx . q{nonce}} = Net::AFP::UAMs::zeropad(
          Crypt::PRNG::random_bytes(${$obj}{nonce_len}), ${$obj}{nonce_len});
        printf qq{nonce is %s\n}, unpack q{H*}, ${$obj}{$pfx. q{nonce}};
        
        ${$obj}{$pfx . q{ctx}} = Crypt::Mode::CBC->new(q{CAST5}, 0);
        my $ciphertext = ${$obj}{ctx}->encrypt(pack(sprintf(q{a[%d]a[%d]},
          @{$obj}{qw(nonce_len signature_len)}), ${$obj}{$pfx . q{nonce}}),
          @{$obj}{$pfx . q{K}, q{S2CIV}});
        return pack sprintf(q{a[%d]a*}, ${$obj}{len}), $Mb, $ciphertext;
    }

    # and you might have guessed based on (various) context clues that
    # this is the second part.
    sub dhx_part2 {
        my($obj, $mask, $message, $pfx) = @_;
        $pfx ||= q{};
        my $len = length pack $mask;

        if (length($message) != (${$obj}{len} + $len)) {
            return $Net::AFP::Result::kFPParamErr;
        }
        my($nonce, @vals) =
          unpack(sprintf(q{a[%d]%s}, ${$obj}{qw(nonce_len)}, $mask),
          ${$obj}{ctx}->decrypt($message, @{$obj}{$pfx . q{K}, q{C2SIV}}));
        if (Crypt::Misc::increment_octets_be(${$obj}{$pfx . q{nonce}}) ne
          $nonce) {
            return $Net::AFP::Result::kFPParamErr;
        }
        return($Net::AFP::Result::kFPNoErr, @vals);
    }

    # just call FPLoginExt under the covers
    sub FPLogin {
        my($obj, $ver, $uam, $ai) = @_;
        my($u, $Ma) = unpack q{C/ax![s]a*}, $ai;
        return($obj->FPLoginExt(AFPVersion => $ver, UAM => $uam,
          UserName => $u, UserAuthInfo => $Ma));
    }

    # stub out the login entry point
    sub FPLoginExt {
        my($obj, %params) = @_;

        srand;
        ${$obj}{id} = int rand 2**16;
        my $resp = dhx_part1($obj, $params{UserAuthInfo});
        return($Net::AFP::Result::kFPAuthContinue,
          UserAuthInfo => $resp, ID => ${$obj}{id});
    }

    # the entry point for the second part of the login conversation
    sub FPLoginCont {
        my($obj, $id, $ai, $resp_r) = @_;
        if (not exists ${$obj}{id} or $id != ${$obj}{id}) {
            return $Net::AFP::Result::kFPParamErr;
        }
        my($rc, $pw) = dhx_part2($obj, sprintf(q{Z[%d]}, ${$obj}{pw_len}),
          $ai);
        delete ${$obj}{id};
        if ($rc != $Net::AFP::Result::kFPNoErr) {
            return $rc;
        }
        printf qq{password is "%s"\n}, $pw;
        if ($pw ne $server_password) {
            return $Net::AFP::Result::kFPUserNotAuth;
        }
        return $rc;
    }

    # change the password - this actually gets called multiple times
    # for different phases of the conversation
    sub FPChangePassword {
        my($obj, $uam, $u, $ai, $resp_r) = @_;
        my($ID, $the_rest) = unpack(q{S>a*}, $ai);
        if (not exists ${$obj}{pc_id}) {
            # this should be the first call to change password,
            # it's staged out in 2 parts
            if ($ID != 0) {
                return $Net::AFP::Result::kFPParamErr;
            }
            ${$obj}{pc_id} = $ID;

            # $the_rest contains Ma.
            my $resp = dhx_part1($obj, $the_rest, q{pc_});
        
            ${$resp_r} = pack q{S>a*}, ${$obj}{pc_id} + 1, $resp;
            return $Net::AFP::Result::kFPAuthContinue;
        }
        # part 2
        if ($ID != ${$obj}{pc_id} + 1) {
            return $Net::AFP::Result::kFPParamErr;
        }
        my($rc, $n, $o) = dhx_part2($obj, sprintf(q{Z[%1$d]Z[%1$d]},
          ${$obj}{pw_len}), $the_rest, q{pc_});
        delete ${$obj}{pc_id};
        if ($rc != $Net::AFP::Result::kFPNoErr) {
            return $rc;
        }
        printf qq{old password is "%s", new password is "%s"\n}, $o, $n;
        if ($o ne $server_password) {
            return $Net::AFP::Result::kFPUserNotAuth;
        }
        if ($server_password eq $n) {
            return $Net::AFP::Result::kFPPwdSameErr;
        }
        $server_password = $n;
        return $rc;
    }
}

my $password;
sub pass_my_password {
    return $password;
}

use Test::More tests => 12;

use Net::AFP::UAMs::DHX;

my $obj = Net::AFP->new();

# try to authenticate with a reasonable password
$server_password = $password = q{foobar};
ok(try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
  q{AFP modern auth, successful});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
  q{AFP old-style auth, successful});
# try to authenticate with a wrong password
$password = q{blahblah};
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP modern auth, bad password});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP old-style auth, bad password});
# this UAM only sends 64 bytes of password, so this fails
$server_password = $password = q{a} x 65;
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP modern auth, password is too long and fails});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP old-style auth, password is too long and fails});
# have a password, then try to change it
$server_password = $password = q{foobar};
my $newpass = q{newpass};
$password = q{blahblah};
# this UAM cares about getting the right "current" password
ok(try_to_change_password($newpass) == $Net::AFP::Result::kFPUserNotAuth,
  q{change password, fails because "old" password is wrong});
$password = $server_password;
ok(try_to_change_password($newpass) == $Net::AFP::Result::kFPNoErr,
  q{change password, succeeds});
# now authenticate with the new password
$password = $newpass;
ok(try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
  q{AFP modern auth, after password change});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
  q{AFP old-style auth, after password change});
# try authenticating with our old password after the change
$password = q{foobar};
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP modern auth, fail with old password});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
  q{AFP old-style auth, fail with old password});

sub try_to_authenticate {
    return Net::AFP::UAMs::DHX::Authenticate($obj, q{AFP3.4}, q{somebody},
      \&pass_my_password);
}

sub try_to_authenticate_old {
    return Net::AFP::UAMs::DHX::Authenticate($obj, q{AFPX03}, q{somebody},
      \&pass_my_password);
}

sub try_to_change_password {
    my ($new_pass) = @_;
    Net::AFP::UAMs::DHX::Authenticate($obj, q{AFPX03}, q{somebody},
      \&pass_my_password);
    # the AFP version needs to be set when doing the password change;
    # all it does internally is pass an empty string for the username
    ${$obj}{AFPVersion} = q{AFPX03};
    # the username and old password don't get checked with this UAM
    return Net::AFP::UAMs::DHX::ChangePassword($obj, q{somebody}, $password,
      $new_pass);
}

# vim: ts=4 et ai sw=4 hls
