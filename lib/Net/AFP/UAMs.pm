package Net::AFP::UAMs;

use strict;
use warnings;
use diagnostics;
use integer;

use Carp;
use Net::AFP::TokenTypes;
use Net::AFP::Result;
use Log::Log4perl;

# Try to import classes for the password based auth methods. If they can't
# be imported, it probably means they have dependencies that can't be
# fulfilled.

my @UAMReg = ();

# uamname is the string (case insensitive) which the server knows the UAM by.
# class is the class name containing an Authenticate method which can be
# used to authenticate to an AFP server that knows the UAM. preference is an
# integer used to indicate what order the UAMs should be chosen in by the
# client. a preference of less than 0 means the UAM will never be selected
# automatically.
sub RegisterUAM {
    my ($uamname, $class, $pref) = @_;

    my $uaminfo = { 'name' => $uamname, 'class' => $class, 'pref' => $pref };
    for my $i (0 .. $#UAMReg) {
        next if $UAMReg[$i]->{'pref'} > $pref;
        @UAMReg = (@UAMReg[0 .. ($i - 1)], $uaminfo, @UAMReg[$i .. $#UAMReg]);
        return;
    }
    push @UAMReg, $uaminfo;
    return;
}

# Where am I being included from? Use our own package name to get the
# inclusion path where we should pull our own UAMs from.
my $incname = __PACKAGE__;
$incname =~ s{::}{/}gsm;
$incname .= '.pm';
# %INC contains the include paths for all currently-imported packages.
my $incpath = $INC{$incname};
$incpath =~ s{[.]pm$}{}sm;
my @uampaths;
if (-d $incpath) {
    opendir my($uamdir), $incpath;
    push @uampaths, map { $incpath . q{/} . $_ } grep { m{[.]pm$}sm } readdir $uamdir;
    closedir $uamdir;
}

# Try including each of them via eval, so that if they explode, it won't
# impair our ability to continue on.
foreach my $uampath (@uampaths) {
    if ($uampath !~ m{^/}sm) {
        $uampath = q{./} . $uampath;
    }
    eval {
        require $uampath;
    } or do {
        carp(sprintf qq{Couldn't include "%s":\n%s\nThis error is not fatal; other UAMs will be tried.}, $uampath, $@);
    }
}

sub GuestAuth {
    my($session, $AFPVersion) = @_;
    my $rc = Net::AFP::UAMs::Anonymous::Authenticate($session, $AFPVersion);
    if ($rc == $kFPNoErr) {
        $session->{'AFPVersion'} = $AFPVersion;
    }
    return $rc;
}

sub PasswordAuth {
    my($session, $AFPVersion, $SupportedUAMs, $UserName, $PwCallback) = @_;
#    die('Need a function ref for password callback')
#            unless ref($PwCallback) eq 'CODE';

    # The AFP server often sets a really lousy UAM order; I should really
    # have a prioritized list of UAMs that we know are good, and try to
    # use the best ones first. OS 9.x likes to specify cleartext auth at
    # the top of the list... not so great.
    my %ReqUAMs = map { lc() => 1 } @{$SupportedUAMs};
    foreach my $uaminfo (@UAMReg) {
        if (not exists $ReqUAMs{lc($uaminfo->{name})}) {
            next;
        }
        if ($uaminfo->{pref} < 0 and scalar(keys %ReqUAMs) > 1) {
            last;
        }
        my $function = $uaminfo->{class} . q{::Authenticate};
        $session->{logger}->debug(sub { sprintf q{%s(): auth function is %s},
          (caller 3)[3], $function);
        $session->{username} = $UserName;
        my $rc;
        {
            ##no critic qw(ProhibitNoStrict)
            no strict qw{refs};
            $rc = &{$function}($session, $AFPVersion, $UserName, $PwCallback);
        }
        if ($rc == $kFPNoErr) {
            $session->{'AFPVersion'} = $AFPVersion;
        }
        return $rc;
    }

    # If we reach this point, none of the UAMs the server knew were available.
    $session->{logger}->error( sub { sprintf q{%s(): Could not find an agreeable } .
      q{UAM for authenticating to server}, (caller 3)[3]});
    return $kFPBadUAM;
}

sub ChangePassword {
    my($session, $SupportedUAMs, $UserName, $OldPW, $NewPW) = @_;

    my %ReqUAMs = map { lc() => 1 } @{$SupportedUAMs};
    foreach my $uaminfo (@UAMReg) {
        if (not exists $ReqUAMs{lc($uaminfo->{'name'})}) {
            next;
        }
        if (not $uaminfo->{class}->can('ChangePassword')) {
            next;
        }
        if ($uaminfo->{pref} < 0 and scalar(keys %ReqUAMs) > 1) {
            last;
        }
        my $function = $uaminfo->{class} . q{::ChangePassword};
        $session->{logger}->debug(sub { sprintf q{%s(): password changing function } .
          q{is %s}, (caller 3)[3], $function);
        my $rc;
        {
            ##no critic qw(ProhibitNoStrict)
            no strict qw{refs};
            $rc = &{$function}($session, $UserName, $OldPW, $NewPW);
        }
        return $rc;
    }

    # If we reach this point, none of the UAMs the server knew were available.
    $session->{logger}->debug(sub { sprintf q{%s(): Could not find valid password } .
      q{changing UAM}, (caller 3)[3] });
    return $kFPBadUAM;
}

1;
# vim: ts=4
