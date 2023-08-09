# This package implements the plain text password authentication (aka
# Cleartxt Passwrd) UAM for the AFP protocol.

package Net::AFP::UAMs::Plaintext;
use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'Cleartxt Passwrd';
use Net::AFP::Versions;
use Net::AFP::Result;
use Carp;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, 0);

sub Authenticate {
    my($session, $AFPVersion, $username, $pw_cb) = @_;

    # Ensure that we've been handed an appropriate object.
    croak("Object MUST be of type Net::AFP!")
            unless ref($session) and $session->isa('Net::AFP');
    
    croak('Password callback MUST be a subroutine ref')
            if ref($pw_cb) ne 'CODE';

    my $pw_data = pack('a8', &{$pw_cb}());
    my $rc;
    
    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc) = $session->FPLoginExt(
                'AFPVersion'    => $AFPVersion,
                'UAM'           => $UAMNAME,
                'UserName'      => $username,
                'UserAuthInfo'  => $pw_data);
        $session->{logger}->debug('FPLoginExt() completed with result code ', $rc);
    }
    else {
        my $authinfo = substr(pack('xC/a*x![s]a8', $username, $pw_data), 1);
        ($rc) = $session->FPLogin($AFPVersion, $UAMNAME, $authinfo);
        $session->{logger}->debug('FPLogin() completed with result code ', $rc);
    }

    return $rc;
}

sub ChangePassword {
    my ($session, $username, $oldPassword, $newPassword) = @_;

    # Ensure that we've been handed an appropriate object.
    croak('Object MUST be of type Net::AFP!')
            unless ref($session) and $session->isa('Net::AFP');

    if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
            $kFPVerAtLeast)) {
        $username = q{};
    }
    return $session->FPChangePassword($UAMNAME, $username,
            pack('a8', $newPassword));
}

1;
# vim: ts=4
