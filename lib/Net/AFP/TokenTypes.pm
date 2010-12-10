package Net::AFP::TokenTypes;

use Exporter qw(import);

our @EXPORT = qw(kLoginWithoutID kLoginWithID kReconnWithID
				 kLoginWithTimeAndID kReconnWithTimeAndID kRecon1Login
				 kRecon1ReconnectLogin kRecon1Refresh kGetKerberosSessionKey);

use constant kLoginWithoutID		=> 0;
use constant kLoginWithID			=> 1;	# deprecated
use constant kReconnWithID			=> 2;	# deprecated
use constant kLoginWithTimeAndID	=> 3;
use constant kReconnWithTimeAndID	=> 4;
use constant kRecon1Login			=> 5;
use constant kRecon1ReconnectLogin	=> 6;
use constant kRecon1Refresh			=> 7;
use constant kGetKerberosSessionKey	=> 8;

1;
# vim: ts=4
