#!/usr/bin/env perl

# test the DHX2 UAM.

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
use Crypt::Misc        qw(increment_octets_be);
use Crypt::Digest::MD5 qw(md5);

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
        if ( length( $_[0] ) > $_[1] ) {
            return substr $_[0], length( $_[0] ) - $_[1], $_[1];
        }
        else {
            return ( qq{\0} x ( $_[1] - length $_[0] ) . $_[0] );
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
            logger => Log::Log4perl->get_logger(),

            # these are values that came from netatalk, by running
            # afpclient with the --debug-afp option. I'm not going
            # to go derive my own large primes for this.
            p =>
q{0xb82f816a7390607cbc3c2d8276a06fdb6f61ecb4ffcae23b67c90c3d39ff3b54b2356c5bad31f42a66ff91faa39915db08aae24320c86c4550666af55e7d7d2644b1a248446281f6bf02a033b44c81873f65d081c41d3f6941d86249829b76f6166e992ab58e3ab794ced8d814fed927bd11640273f36174adc61e12a43cb57b},
            g => 5,

            # initialization vectors
            C2SIV => q{LWallace},
            S2CIV => q{CJalbert},

            # length of key values, p, etc.
            len => 128,

            # length of nonces
            nonce_len => 16,

            # max password length this UAM can handle
            pw_len => 256,
        );
        return $obj;
    }

    # part 1 of the DHX2 server-side conversation, abstracted so both
    # the auth and password change paths can use it.
    sub dhx2_part1 {
        my ( $obj, $pfx ) = @_;
        $pfx ||= q{};
        srand;
        ${$obj}{ $pfx . q{id} } = int rand 2**16;
        ( ${$obj}{ $pfx . q{dh} } = Crypt::PK::DH->new() )
          ->generate_key( { p => ${$obj}{p}, g => ${$obj}{g} } );
        my $Mb = Net::AFP::UAMs::zeropad(
            ${$obj}{ $pfx . q{dh} }->export_key_raw(q{public}),
            ${$obj}{len} );
        printf qq{server pubkey is %s\n}, unpack q{H*}, $Mb;

        return (
            ID           => ${$obj}{ $pfx . q{id} },
            UserAuthInfo => pack sprintf( q{L>S>a[%1$d]a[%1$d]}, ${$obj}{len} ),
            @{$obj}{qw(g len)},
            Net::AFP::UAMs::zeropad(
                pack( q{H*}, substr( ${$obj}{p}, 2 ) ),
                ${$obj}{len}
            ),
            $Mb
        );
    }

    # and here's part two.
    sub dhx2_part2 {
        my ( $obj, $message, $pfx ) = @_;
        $pfx ||= q{};

        if ( length($message) != ( ${$obj}{len} + ${$obj}{nonce_len} ) ) {
            return $Net::AFP::Result::kFPParamErr;
        }
        my ( $Ma, $ciphertext ) =
          unpack sprintf( q{a[%d]a[%d]}, ${$obj}{len}, ${$obj}{nonce_len} ),
          $message;
        printf qq{client pubkey is %s\n}, unpack q{H*}, $Ma;

        ${$obj}{ $pfx . q{K} } = Net::AFP::UAMs::zeropad(
            Crypt::Digest::MD5::md5(
                Net::AFP::UAMs::zeropad(
                    ${$obj}{ $pfx . q{dh} }->shared_secret(
                        Crypt::PK::DH->new()->import_key_raw(
                            $Ma, q{public},
                            { p => ${$obj}{p}, g => ${$obj}{g} }
                        )
                    ),
                    ${$obj}{len}
                )
            ),
            16
        );
        printf qq{md5 of key is %s\n}, unpack q{H*}, ${$obj}{ $pfx . q{K} };
        ${$obj}{ $pfx . q{ctx} }       = Crypt::Mode::CBC->new( q{CAST5}, 0 );
        ${$obj}{ $pfx . q{cli_nonce} } = Net::AFP::UAMs::zeropad(
            ${$obj}{ $pfx . q{ctx} }
              ->decrypt( $ciphertext, @{$obj}{ $pfx . q{K}, q{C2SIV} } ),
            ${$obj}{nonce_len}
        );
        printf qq{client nonce is %s\n},
          unpack q{H*}, ${$obj}{ $pfx . q{cli_nonce} };
        ${$obj}{ $pfx . q{srv_nonce} } =
          Crypt::PRNG::random_bytes( ${$obj}{nonce_len} );
        printf qq{server nonce is %s\n},
          unpack q{H*}, ${$obj}{ $pfx . q{srv_nonce} };
        $ciphertext = ${$obj}{ $pfx . q{ctx} }->encrypt(
            pack(
                sprintf( q{a[%1$d]a[%1$d]}, ${$obj}{nonce_len} ),
                Net::AFP::UAMs::zeropad(
                    Crypt::Misc::increment_octets_be(
                        ${$obj}{ $pfx . q{cli_nonce} }
                    ),
                    ${$obj}{nonce_len}
                ),
                Net::AFP::UAMs::zeropad(
                    ${$obj}{ $pfx . q{srv_nonce} },
                    ${$obj}{nonce_len}
                )
            ),
            @{$obj}{ $pfx . q{K}, q{S2CIV} }
        );
        return ( $Net::AFP::Result::kFPAuthContinue, $ciphertext );
    }

    # wait, there's a *third* part? yep.
    sub dhx2_part3 {
        my ( $obj, $mask, $ai, $pfx ) = @_;
        $pfx ||= q{};
        my $len = length pack $mask;

        if ( length($ai) != ( ${$obj}{nonce_len} + $len ) ) {
            return $Net::AFP::Result::kFPParamErr;
        }
        my ( $nonce, @vals ) =
          unpack sprintf( q{a[%d]%s}, ${$obj}{nonce_len}, $mask ),
          ${$obj}{ctx}->decrypt( $ai, @{$obj}{ $pfx . q{K}, q{C2SIV} } );

        # probably need to zeropad here too
        if (
            Net::AFP::UAMs::zeropad(
                Crypt::Misc::increment_octets_be(
                    ${$obj}{ $pfx . q{srv_nonce} }
                ),
                ${$obj}{nonce_len}
            ) ne $nonce
          )
        {
            return $Net::AFP::Result::kFPParamErr;
        }
        return ( $Net::AFP::Result::kFPNoErr, @vals );
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
        return ( $Net::AFP::Result::kFPAuthContinue, dhx2_part1($obj) );
    }

    # the entry point for the subsequent parts of the login conversation
    # (this UAM has two!)
    sub FPLoginCont {
        my ( $obj, $id, $ai, $resp_r ) = @_;
        if ( exists ${$obj}{id} and $id == ${$obj}{id} ) {
            my ( $rc, $resp ) = dhx2_part2( $obj, $ai );
            if ( $rc == $Net::AFP::Result::kFPAuthContinue ) {
                ${$resp_r} = { UserAuthInfo => $resp, ID => ${$obj}{id} + 1 };
            }
            else {
                delete ${$obj}{id};
            }
            return $rc;
        }
        elsif ( exists ${$obj}{id} and $id == ${$obj}{id} + 1 ) {
            my ( $rc, $pw ) =
              dhx2_part3( $obj, sprintf( q{Z[%d]}, ${$obj}{pw_len} ), $ai );
            delete ${$obj}{id};
            if ( $rc != $Net::AFP::Result::kFPNoErr ) {
                return $rc;
            }
            printf qq{password is "%s"\n}, $pw;
            if ( $pw ne $server_password ) {
                return $Net::AFP::Result::kFPUserNotAuth;
            }
            return $rc;
        }

        # if this ever happens, it all went to hell
        return $Net::AFP::Result::kFPParamErr;
    }

    # change the password - this actually gets called multiple times
    # for different phases of the conversation - this UAM has three!
    sub FPChangePassword {
        my ( $obj, $uam, $u, $ai, $resp_r ) = @_;
        if ( not exists ${$obj}{pc_id} ) {
            my (%resp) = dhx2_part1( $obj, q{pc_} );
            ${$resp_r} = pack q{S>a*}, @resp{qw(ID UserAuthInfo)};
            printf qq{response body is %s\n}, unpack q{H*}, ${$resp_r};
            return $Net::AFP::Result::kFPAuthContinue;
        }
        my ( $id, $the_rest ) = unpack q{S>a*}, $ai;
        printf qq{id is %d\n}, $id;
        if ( $id == ${$obj}{pc_id} ) {
            my ( $rc, $resp ) = dhx2_part2( $obj, $the_rest, q{pc_} );
            if ( $rc == $Net::AFP::Result::kFPAuthContinue ) {
                ${$resp_r} = pack q{S>a*}, ${$obj}{pc_id} + 1, $resp;
            }
            else {
                delete ${$obj}{pc_id};
            }
            return $rc;
        }
        elsif ( $id == ${$obj}{pc_id} + 1 ) {
            my ( $rc, $n, $o ) =
              dhx2_part3( $obj, sprintf( q{Z[%1$d]Z[%1$d]}, ${$obj}{pw_len} ),
                $the_rest, q{pc_} );
            delete ${$obj}{pc_id};
            if ( $rc != $Net::AFP::Result::kFPNoErr ) {
                return $rc;
            }
            printf qq{old password is "%s", new password is "%s"\n}, $o, $n;
            if ( $o ne $server_password ) {
                return $Net::AFP::Result::kFPUserNotAuth;
            }
            if ( $server_password eq $n ) {
                return $Net::AFP::Result::kFPPwdSameErr;
            }
            $server_password = $n;
            return $rc;
        }

        # this should never happen, but if it does, things went bad
        return $Net::AFP::Result::kFPParamErr;
    }
}

my $password;

sub pass_my_password {
    return $password;
}

use Test::More tests => 12;

use Net::AFP::UAMs::DHX2;

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

# this UAM handles up to 256 bytes of password. what are the odds.
$server_password = $password = q{a} x 257;
ok(
    try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP modern auth, password is too long and fails}
);
ok(
    try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP old-style auth, password is too long and fails}
);

# have a password, then try to change it
$server_password = $password = q{foobar};
my $newpass = q{newpass};
$password = q{blahblah};

# this UAM cares about getting the right "current" password
ok(
    try_to_change_password($newpass) == $Net::AFP::Result::kFPUserNotAuth,
    q{change password, fails because "old" password is wrong}
);
$password = $server_password;
ok( try_to_change_password($newpass) == $Net::AFP::Result::kFPNoErr,
    q{change password, succeeds} );

# now authenticate with the new password
$password = $newpass;
ok(
    try_to_authenticate() == $Net::AFP::Result::kFPNoErr,
    q{AFP modern auth, after password change}
);
ok(
    try_to_authenticate_old() == $Net::AFP::Result::kFPNoErr,
    q{AFP old-style auth, after password change}
);

# try authenticating with our old password after the change
$password = q{foobar};
ok( try_to_authenticate() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP modern auth, fail with old password} );
ok( try_to_authenticate_old() == $Net::AFP::Result::kFPUserNotAuth,
    q{AFP old-style auth, fail with old password} );

sub try_to_authenticate {
    return Net::AFP::UAMs::DHX2::Authenticate( $obj, q{AFP3.4}, q{somebody},
        \&pass_my_password );
}

sub try_to_authenticate_old {
    return Net::AFP::UAMs::DHX2::Authenticate( $obj, q{AFPX03}, q{somebody},
        \&pass_my_password );
}

sub try_to_change_password {
    my ($new_pass) = @_;
    Net::AFP::UAMs::DHX2::Authenticate( $obj, q{AFPX03}, q{somebody},
        \&pass_my_password );

    # the AFP version needs to be set when doing the password change;
    # all it does internally is pass an empty string for the username
    ${$obj}{AFPVersion} = q{AFPX03};

    # the username and old password don't get checked with this UAM
    return Net::AFP::UAMs::DHX2::ChangePassword( $obj, q{somebody}, $password,
        $new_pass );
}

# vim: ts=4 et ai sw=4 hls
