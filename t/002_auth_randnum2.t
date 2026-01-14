#!/usr/bin/env perl

# test the 2-way randnum UAM.

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
        ${$obj}{logger} = Log::Log4perl->get_logger();
        return $obj;
    }

    # just call FPLoginExt under the covers
    sub FPLogin {
        my ( $obj, $ver, $uam, $ai ) = @_;
        my ($u) = unpack q{C/a}, $ai;
        return (
            $obj->FPLoginExt(
                AFPVersion => $ver,
                UAM        => $uam,
                UserName   => $u
            )
        );
    }

    # stub out the login entry point
    sub FPLoginExt {
        my ( $obj, %params ) = @_;

        srand;
        ${$obj}{id} = int rand 2**16;
        ${$obj}{r}  = Crypt::PRNG::random_bytes(8);
        return (
            $Net::AFP::Result::kFPAuthContinue,
            UserAuthInfo => ${$obj}{r},
            ID           => ${$obj}{id}
        );
    }

    # the entry point for the second part of the login conversation
    sub FPLoginCont {
        my ( $obj, $id, $ai, $resp_r ) = @_;
        my ( $cl_crypted, $rn ) = unpack( q{a[8]a[8]}, $ai );

        # turn the password into a bit vector, lop off the first bit,
        # and move it to the end
        ( my $bin_key = unpack q{B*}, pack q{a[8]}, $server_password ) =~
          s/^([01])(.*)$/$2$1/sm;

        # encrypt the random number with the transformed password
        my $dh      = Crypt::Cipher::DES->new( pack q{B*}, $bin_key );
        my $crypted = $dh->encrypt( ${$obj}{r} );
        if ( ( $crypted ne $cl_crypted ) or ( $id != ${$obj}{id} ) ) {
            return $Net::AFP::Result::kFPUserNotAuth;
        }

        # also encrypt the password with the client's random number,
        # and see if we agree
        ${$resp_r} = { UserAuthInfo => $dh->encrypt($rn) };
        return $Net::AFP::Result::kFPNoErr;
    }
}

my $password;

sub pass_my_password {
    return $password;
}

use Test::More tests => 6;

use Net::AFP::UAMs::Randnum2;

my $obj = Net::AFP->new();

# try to authenticate with a reasonable password
$server_password = $password = q{foobar};
ok( try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
    q{AFP modern auth, successful} );
ok( try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
    q{AFP old-style auth, successful} );

# try to authenticate with a wrong password
$password = q{blahblah};
ok( try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP modern auth, bad password} );
ok( try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP old-style auth, bad password} );

# this UAM crypts only 8 chars of the password, so it works
$server_password = $password = q{thisistoolong};
ok(
    try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
    q{AFP modern auth, password too long but succeeds}
);
ok(
    try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
    q{AFP old-style auth, password too long but succeeds}
);

sub try_to_authenticate {
    return Net::AFP::UAMs::Randnum2::Authenticate( $obj, q{AFP3.4},
        q{somebody}, \&pass_my_password );
}

sub try_to_authenticate_old {
    return Net::AFP::UAMs::Randnum2::Authenticate( $obj, q{AFPX03},
        q{somebody}, \&pass_my_password );
}

# vim: ts=4 et ai sw=4 hls
