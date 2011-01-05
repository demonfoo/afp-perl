package Net::AFP::TokenTypes;

use Exporter qw(import);

our @EXPORT = qw(kLoginWithoutID kLoginWithID kReconnWithID
                 kLoginWithTimeAndID kReconnWithTimeAndID kRecon1Login
                 kRecon1ReconnectLogin kRecon1Refresh kGetKerberosSessionKey);

use constant kLoginWithoutID        => 0;   # AFP 3.0
use constant kLoginWithID           => 1;   # AFP 3.0; deprecated
use constant kReconnWithID          => 2;   # AFP 3.1; deprecated
use constant kLoginWithTimeAndID    => 3;   # AFP 3.1
use constant kReconnWithTimeAndID   => 4;   # AFP 3.1
use constant kRecon1Login           => 5;   # AFP 3.1+ (10.5)
use constant kRecon1ReconnectLogin  => 6;   # AFP 3.1+ (10.5)
use constant kRecon1Refresh         => 7;   # AFP 3.1+ (10.5)
use constant kGetKerberosSessionKey => 8;   # AFP 3.1+ (10.5)

1;
# vim: ts=4
