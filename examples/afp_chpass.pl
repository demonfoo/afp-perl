#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

use Net::AFP::Helpers;
use Net::AFP::UAMs;
use Net::AFP::Result;
use Term::ReadPassword;

my($url) = @ARGV;

unless ($url) {
    usage();
}

my $old_pass;
my $pw_cb =  sub {
    my(%values) = @_;
    my $prompt = 'Password for ' . $values{'username'} .
            ' at ' . $values{'host'} . ': ';
    unless ($values{'password'}) {
        $values{'password'} = read_password($prompt);
    }
    $old_pass = $values{'password'};
    return $values{'password'};
};

my($session, %values) = do_afp_connect($pw_cb, $url);
unless (ref($session) && $session->isa('Net::AFP')) {
    exit($session);
}

my $new_pass = read_password('Enter your new password: ');
my $check_pass = read_password('Reenter your password: ');

if ($new_pass eq $check_pass) {
    my $rc = Net::AFP::UAMs::ChangePassword($session,
            $values{'username'}, $old_pass, $new_pass);
    if ($rc != kFPNoErr) {
        print "Server responded: ", afp_strerror($rc), " (", $rc, ")\n";
    }
}
else {
    print "ERROR: Passwords did not match!\n";
}

$session->close();

sub usage {
    print <<'_EOT_';

afp_chpass.pl - AFP password changing tool

Usage: afp_chpass.pl [AFP URL]


_EOT_

    exit(1);
}