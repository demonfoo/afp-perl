package Net::AFP::FileParms;

use constant kFPAttributeBit		=> 0x0001;
use constant kFPParentDirIDBit		=> 0x0002;
use constant kFPCreateDateBit		=> 0x0004;
use constant kFPModDateBit			=> 0x0008;
use constant kFPBackupDateBit		=> 0x0010;
use constant kFPFinderInfoBit		=> 0x0020;
use constant kFPLongNameBit			=> 0x0040;
use constant kFPShortNameBit		=> 0x0080;
use constant kFPNodeIDBit			=> 0x0100;
use constant kFPDataForkLenBit		=> 0x0200;
use constant kFPRsrcForkLenBit		=> 0x0400;
use constant kFPExtDataForkLenBit	=> 0x0800;
use constant kFPLaunchLimitBit		=> 0x1000;
use constant kFPUTF8NameBit			=> 0x2000;
use constant kFPExtRsrcForkLenBit	=> 0x4000;
use constant kFPUnixPrivsBit		=> 0x8000;

1;
# vim: ts=4
