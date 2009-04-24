package Net::AFP::DirParms;

use constant kFPAttributeBit		=> 0x0001;
use constant kFPParentDirIDBit		=> 0x0002;
use constant kFPCreateDateBit		=> 0x0004;
use constant kFPModDateBit			=> 0x0008;
use constant kFPBackupDateBit		=> 0x0010;
use constant kFPFinderInfoBit		=> 0x0020;
use constant kFPLongNameBit			=> 0x0040;
use constant kFPShortNameBit		=> 0x0080;
use constant kFPNodeIDBit			=> 0x0100;
use constant kFPOffspringCountBit	=> 0x0200;
use constant kFPOwnerIDBit			=> 0x0400;
use constant kFPGroupIDBit			=> 0x0800;
use constant kFPAccessRightsBit		=> 0x1000;
# Valid in AFP 2.2 and below
use constant kFPProDOSInfoBit		=> 0x2000;
# Valid in AFP 3.0 and up
use constant kFPUTF8NameBit			=> 0x2000;
use constant kFPUnixPrivsBit		=> 0x8000;

1;
# vim: ts=4
