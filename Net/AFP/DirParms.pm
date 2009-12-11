package Net::AFP::DirParms;

use constant kFPAttributeBit		=> 0x00001;
use constant kFPParentDirIDBit		=> 0x00002;
use constant kFPCreateDateBit		=> 0x00004;
use constant kFPModDateBit			=> 0x00008;
use constant kFPBackupDateBit		=> 0x00010;
use constant kFPFinderInfoBit		=> 0x00020;
use constant kFPLongNameBit			=> 0x00040;
use constant kFPShortNameBit		=> 0x00080;
use constant kFPNodeIDBit			=> 0x00100;
use constant kFPOffspringCountBit	=> 0x00200;
use constant kFPOwnerIDBit			=> 0x00400;
use constant kFPGroupIDBit			=> 0x00800;
use constant kFPAccessRightsBit		=> 0x01000;
use constant kFPProDOSInfoBit		=> 0x02000; # AFP <= 2.2
use constant kFPUTF8NameBit			=> 0x02000; # AFP >= 3.0
use constant kFPUnixPrivsBit		=> 0x08000; # AFP >= 3.0
use constant kFPUUID				=> 0x10000; # AFP >= 3.0

1;
# vim: ts=4
