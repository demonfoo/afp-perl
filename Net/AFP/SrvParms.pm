package Net::AFP::SrvParms;

use constant kSupportsCopyFile		=> 0x0001;
use constant kSupportsChgPwd		=> 0x0002;
# This bit was added as of AFP v2.1.
use constant kDontAllowSavePwd		=> 0x0004;
# This bit was added, along with the FPGetSrvrMsg operation, as of AFP v2.1.
use constant kSupportsSrvrMsg		=> 0x0008;
use constant kSrvrSig				=> 0x0010;
use constant kSupportsTCP			=> 0x0020;
use constant kSupportsSrvrNotify	=> 0x0040;
use constant kSupportsReconnect		=> 0x0080;
use constant kSupportsDirServices	=> 0x0100;
use constant kSupportsUTF8SrvrName	=> 0x0200;
use constant kSupportsUUIDs			=> 0x0400;
use constant kSupportsSuperClient	=> 0x8000;

1;
# vim: ts=4
