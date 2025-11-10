#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

use Net::AFP::Helpers;
use Net::AFP::UAMs;
use Net::AFP::Result;
use Net::AFP::SrvParms;
use Term::ReadPassword;
use English qw(-no_match_vars);
use Log::Log4perl;

my $logconf = <<'_EOT_';
log4perl.appender.AppLogging = Log::Log4perl::Appender::Screen
log4perl.appender.AppLogging.layout = PatternLayout
log4perl.appender.AppLogging.layout.ConversionPattern = [%P] %F line: %L %c - %m%n
log4perl.appender.AppLogging.Threshold = INFO

log4perl.appender.Console = Log::Log4perl::Appender::ScreenColoredLevels
log4perl.appender.Console.layout = SimpleLayout

log4perl.logger = INFO, AppLogging
_EOT_

Log::Log4perl->init(\$logconf);

my($url) = @ARGV;

if (not $url) {
    usage();
}

my $old_pass;
my $pw_cb =  sub {
    my(%values) = @_;
    my $prompt = sprintf q{Password for %s at %s: }, @values{qw(username host)};
    if (not $values{password}) {
        $values{password} = read_password($prompt);
    }
    $old_pass = $values{password};
    return $values{password};
};

my $si;
my($session, %values) = do_afp_connect($pw_cb, $url, \$si);
if (not ref $session or not $session->isa(q{Net::AFP})) {
    exit 2;
}

if (not($si->{Flags} & $kSupportsChgPwd)) {
    print qq{ERROR: Server does not support password changing\n};
    $session->close();
    exit 2;
}

my $new_pass   = read_password(q{Enter your new password: });
my $check_pass = read_password(q{Reenter your password: });

my $rv = 0;

if ($new_pass eq $check_pass) {
    my $uamlist = $si->{UAMs};
    if (exists $values{UAM}) {
        $uamlist = [ $values{UAM} ];
    }
    my $rc = Net::AFP::UAMs::ChangePassword($session, $si->{UAMs},
            $values{username}, $old_pass, $new_pass);
    if ($rc != $kFPNoErr) {
        printf qq{ERROR: Server responded: %s (%d)\n}, afp_strerror($rc), $rc;
        $rv = 2;
    }
    else {
        print qq{No error, password changed successfully\n};
    }
}
else {
    print qq{ERROR: Passwords did not match!\n};
    $rv = 3;
}

$session->close();

exit $rv;

sub usage {
    print <<"_EOT_";

${PROGRAM_NAME} - AFP password changing tool

Usage: ${PROGRAM_NAME} [AFP URL]

Change password on an AFP server.

Returns 0 on successful password change, 1 if arguments could not be
parsed, 2 on server error, 3 on password mismatch.

_EOT_

    exit 1;
}
# vim: ts=4 fdm=marker sw=4 et
