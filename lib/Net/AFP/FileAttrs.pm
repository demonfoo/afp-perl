package Net::AFP::FileAttrs;

use constant kFPInvisibleBit        => 0x0001;
use constant kFPMultiUserBit        => 0x0002;
use constant kFPSystemBit           => 0x0004;  # AFP 2.0
use constant kFPDAlreadyOpenBit     => 0x0008;
use constant kFPRAlreadyOpenBit     => 0x0010;
use constant kFPWriteInhibitBit     => 0x0020;  # Was "ReadOnly" before AFP 2.0
use constant kFPBackUpNeededBit     => 0x0040;  # AFP 2.0
use constant kFPRenameInhibitBit    => 0x0080;  # AFP 2.0
use constant kFPDeleteInhibitBit    => 0x0100;  # AFP 2.0
use constant kFPCopyProtectBit      => 0x0400;  # AFP 2.0
use constant kFPSetClearBit         => 0x8000;

1;
# vim: ts=4 et ai
