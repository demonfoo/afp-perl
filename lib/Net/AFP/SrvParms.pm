package Net::AFP::SrvParms;

use Exporter qw(import);

our @EXPORT = qw(kSupportsCopyFile kSupportsChgPwd kDontAllowSavePwd
                 kSupportsSrvrMsg kSrvrSig kSupportsTCP kSupportsSrvrNotify
                 kSupportsReconnect kSupportsDirServices kSupportsUTF8SrvrName
                 kSupportsUUIDs kSupportsExtSleep kSupportsSuperClient);

use constant kSupportsCopyFile      => 0x0001;
use constant kSupportsChgPwd        => 0x0002;
use constant kDontAllowSavePwd      => 0x0004;  # AFP 2.1
use constant kSupportsSrvrMsg       => 0x0008;  # AFP 2.1
use constant kSrvrSig               => 0x0010;  # AFP 2.2
use constant kSupportsTCP           => 0x0020;  # AFP 2.2
use constant kSupportsSrvrNotify    => 0x0040;  # AFP 2.2
use constant kSupportsReconnect     => 0x0080;  # AFP 3.0
use constant kSupportsDirServices   => 0x0100;  # AFP 3.0
use constant kSupportsUTF8SrvrName  => 0x0200;  # AFP 3.2
use constant kSupportsUUIDs         => 0x0400;  # AFP 3.2
use constant kSupportsExtSleep      => 0x0800;  # AFP 3.2+ (10.5)
use constant kSupportsSuperClient   => 0x8000;

1;
# vim: ts=4
