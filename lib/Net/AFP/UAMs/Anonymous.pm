# This package implements the anonymous (aka 'No User Authent') UAM for the
# AFP protocol.

package Net::AFP::UAMs::Anonymous;
use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'No User Authent';
use Net::AFP::Result;
use Net::AFP::Versions;
use Carp;

Net::AFP::UAMs::RegisterUAM($UAMNAME, __PACKAGE__, -10);

sub Authenticate {
    # The latter two args (username and a password callback function) can
    # be ignored here, since they're not applicable for anonymous auth.
    my($session, $AFPVersion) = @_;
    print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

    # Ensure that we've been handed an appropriate object.
    croak("Object MUST be of type Net::AFP!")
            unless ref($session) and $session->isa('Net::AFP');
    
    my $rc;

    if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
            $kFPVerAtLeast)) {
        ($rc) = $session->FPLoginExt(
                AFPVersion  => $AFPVersion,
                UAM         => $UAMNAME,
                UserName    => q{});
        print q{FPLoginExt() completed with result code }, $rc, q{\n}
                if defined $::__AFP_DEBUG;
    }
    else {
        ($rc) = $session->FPLogin($AFPVersion, $UAMNAME, q{});
        print q{FPLogin() completed with result code }, $rc, q{\n}
                if defined $::__AFP_DEBUG;
    }

    return $rc;
}

1;
# vim: ts=4
