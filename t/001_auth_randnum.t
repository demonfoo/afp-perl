#!/usr/bin/env perl

# test the randnum UAM instead.

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
use Crypt::Cipher::DES;

# just do this so it doesn't whine
Log::Log4perl->easy_init($ERROR);

# we need a mostly-empty "Net::AFP::UAMs" that pretends to register
# a UAM when it loads, so that we can call its methods.
{
    package Net::AFP::UAMs;

    sub RegisterUAM {
        # do nothing, this is just a placeholder
    }
}

my $server_password;
# just pretend to be enough of Net::AFP to test this UAM
{
    package Net::AFP;

    # just create an empty object with a logger
    sub new {
        my $obj = {};
        bless $obj, $_[0];
        # gotta provide this for all the stuff that uses it.
        ${$obj}{logger} = Log::Log4perl->get_logger();
        return $obj;
    }

    # actually just call FPLoginExt rather than implementing this
    # in two places?
    sub FPLogin {
        my($obj, $ver, $uam, $ai) = @_;
        my($u) = unpack q{C/a}, $ai;
        return($obj->FPLoginExt(AFPVersion => $ver, UAM => $uam,
          UserName => $u));
    }

    # this part simply generates a "random number", saves it, and
    # returns it.
    sub FPLoginExt {
        my($obj, %params) = @_;

        srand;
        ${$obj}{id} = int rand 2**16;
        ${$obj}{r} = Crypt::PRNG::random_bytes(8);
        return($Net::AFP::Result::kFPAuthContinue,
          UserAuthInfo => ${$obj}{r}, ID => ${$obj}{id});
    }

    # now use that random number we saved, "encrypt" the password
    # with it, and compare to the value the caller supplies.
    sub FPLoginCont {
        my($obj, $id, $ai, $resp_r) = @_;
        my $dh = Crypt::Cipher::DES->new(pack q{a[8]}, $server_password);
        my $crypted = $dh->encrypt(${$obj}{r});
        if (($crypted eq $ai) and ($id == ${$obj}{id})) {
            return $Net::AFP::Result::kFPNoErr;
        }
        return $Net::AFP::Result::kFPUserNotAuth;
    }

    # change the password
    sub FPChangePassword {
        my($obj, $uam, $u, $ai, $resp_r) = @_;
        my($o, $n) = unpack(q{a[8]a[8]}, $ai);
        # try to decrypt the "new" hash with the password we already
        # know
        my $newpassword =
          Crypt::Cipher::DES->new(pack q{a[8]}, $server_password)
          ->decrypt($n);
        my $odh = Crypt::Cipher::DES->new($newpassword);
        # try to encrypt the "current" password with what we _think_
        # the "new" password is; if they don't match, something is wrong
        if ($odh->encrypt(pack q{a[8]}, $server_password) ne $o) {
            return $Net::AFP::Result::kFPUserNotAuth;
        }
        if ($server_password eq $newpassword) {
            return $Net::AFP::Result::kFPPwdSameErr;
        }
        # the password is now changed
        $server_password = $newpassword;
        return $Net::AFP::Result::kFPNoErr;
    }
}

my $password;
sub pass_my_password {
    return $password;
}

use Test::More tests => 12;

use Net::AFP::UAMs::Randnum;

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
# this UAM crypts only 8 chars of the password, so it works
$server_password = $password = q{thisistoolong};
ok(try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
  q{AFP modern auth, password too long but succeeds});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
  q{AFP old-style auth, password too long but succeeds});
# have a password, then try to change it
$server_password = $password = q{foobar};
my $newpass = q{newpass};
$password = q{blahblah};
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
    return Net::AFP::UAMs::Randnum::Authenticate($obj, q{AFP3.4}, q{somebody},
       \&pass_my_password);
}

sub try_to_authenticate_old {
    return Net::AFP::UAMs::Randnum::Authenticate($obj, q{AFPX03}, q{somebody},
      \&pass_my_password);
}

sub try_to_change_password {
    my ($new_pass) = @_;
    Net::AFP::UAMs::Randnum::Authenticate($obj, q{AFPX03}, q{somebody},
      \&pass_my_password);
    # the AFP version needs to be set when doing the password change;
    # all it does internally is pass an empty string for the username
    ${$obj}{AFPVersion} = q{AFPX03};
    # the username and old password don't get checked with this UAM
    return Net::AFP::UAMs::Randnum::ChangePassword($obj, q{somebody},
      $password, $new_pass);
}

# vim: ts=4 et ai sw=4 hls
