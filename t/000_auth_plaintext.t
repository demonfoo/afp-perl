#!/usr/bin/env perl

# just a simple-ish example test for a UAM.

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
        ${$obj}{logger} = Log::Log4perl->get_logger();
        return $obj;
    }

    # just call FPLoginExt under the covers
    sub FPLogin {
        my($obj, $ver, $uam, $ai) = @_;
        # the alignment for this data is slightly whack, but that's what
        # a real AFP server would expect.
        my($u, $p) = unpack q{xC/ax![s]Z[8]}, qq{\0} . $ai;
        return($obj->FPLoginExt(AFPVersion => $ver, UAM => $uam,
          UserName => $u, UserAuthInfo => pack q{a[8]}, $p));
    }

    # stub out the login entry point
    sub FPLoginExt {
        my($obj, %params) = @_;
        # password is padded with nulls, so make sure that's undone
        my($p) = unpack q{Z[8]}, $params{UserAuthInfo};
        return( ($p eq $server_password) ? $Net::AFP::Result::kFPNoErr : $Net::AFP::Result::kFPUserNotAuth);
    }

    # change the password
    sub FPChangePassword {
        my($obj, $uam, $u, $ai, $resp_r) = @_;
        # other UAMs confirm the existing password, but not this one
        my $np = unpack q{Z[8]}, $ai;
        if ($server_password eq $np) {
            return $Net::AFP::Result::kFPPwdSameErr;
        }
        $server_password = $np;
        return $Net::AFP::Result::kFPNoErr;
    }
}

my $password;
sub pass_my_password {
    return $password;
}

use Test::More tests => 11;

use Net::AFP::UAMs::Plaintext;

my $obj = Net::AFP->new();

# try to authenticate with a reasonable password
$password = $server_password = q{foobar};
ok(try_to_authenticate() == $Net::AFP::Result::kFPNoErr, q{AFP modern auth, successful});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr, q{AFP old-style auth, successful});
# try to authenticate with a wrong password
$password = q{blahblah};
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth, q{AFP modern auth, bad password});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth, q{AFP old-style auth, bad password});
# this UAM only handles passwords up to 8 chars
$password = $server_password = q{thisistoolong};
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth, q{AFP modern auth, fails because of too-long password});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth, q{AFP old-style auth, fails because of too-long password});
# have a password, then try to change it
$password = $server_password = q{foobar};
my $newpass = q{newpass};
ok(try_to_change_password($newpass) == $Net::AFP::Result::kFPNoErr, q{change password, this can only succeed});
# now authenticate with the new password
$password = $newpass;
ok(try_to_authenticate() == $Net::AFP::Result::kFPNoErr, q{AFP modern auth, after password change});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr, q{AFP old-style auth, after password change});
# try authenticating with our old password after the change
$password = q{foobar};
ok(try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth, q{AFP modern auth, fail with old password});
ok(try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth, q{AFP old-style auth, fail with old password});

sub try_to_authenticate {
    return Net::AFP::UAMs::Plaintext::Authenticate($obj, q{AFP3.4},
      q{somebody}, \&pass_my_password);
}

sub try_to_authenticate_old {
    return Net::AFP::UAMs::Plaintext::Authenticate($obj, q{AFPX03},
      q{somebody}, \&pass_my_password);
}

sub try_to_change_password {
    my ($new_pass) = @_;
    Net::AFP::UAMs::Plaintext::Authenticate($obj, q{AFPX03}, q{somebody},
      \&pass_my_password);
    # the AFP version needs to be set when doing the password change;
    # all it does internally is pass an empty string for the username
    ${$obj}{AFPVersion} = q{AFPX03};
    # the username and old password don't get checked with this UAM
    return Net::AFP::UAMs::Plaintext::ChangePassword($obj, q{somebody},
      q{whatev}, $new_pass);
}

# vim: ts=4 et ai sw=4 hls
