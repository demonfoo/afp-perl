package Net::AFP::TokenTypes;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kLoginWithoutID $kLoginWithID $kReconnWithID
                 $kLoginWithTimeAndID $kReconnWithTimeAndID $kRecon1Login
                 $kRecon1ReconnectLogin $kRecon1Refresh
                 $kGetKerberosSessionKey);

Readonly our $kLoginWithoutID           => 0;   # AFP 3.0
Readonly our $kLoginWithID              => 1;   # AFP 3.0; deprecated
Readonly our $kReconnWithID             => 2;   # AFP 3.1; deprecated
Readonly our $kLoginWithTimeAndID       => 3;   # AFP 3.1
Readonly our $kReconnWithTimeAndID      => 4;   # AFP 3.1
Readonly our $kRecon1Login              => 5;   # AFP 3.1+ (10.3)
Readonly our $kRecon1ReconnectLogin     => 6;   # AFP 3.1+ (10.3)
Readonly our $kRecon1Refresh            => 7;   # AFP 3.1+ (10.3)
Readonly our $kGetKerberosSessionKey    => 8;   # AFP 3.1+ (10.3)

1;
# vim: ts=4
