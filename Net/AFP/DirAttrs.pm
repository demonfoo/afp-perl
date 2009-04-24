package Net::AFP::DirAttrs;

use constant kFPInvisibleBit		=> 0x0001;
use constant kFPIsExpFolderBit		=> 0x0002;
use constant kFPSystemBit			=> 0x0004;
use constant kFPMountedBit			=> 0x0008;
use constant kFPInExpFolderBit		=> 0x0010;
use constant kFPBackUpNeededBit		=> 0x0040;
use constant kFPRenameInhibitBit	=> 0x0080;
use constant kFPDeleteInhibitBit	=> 0x0100;
use constant kFPSetClearBit			=> 0x8000;

1;
# vim: ts=4
