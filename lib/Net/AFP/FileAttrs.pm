package Net::AFP::FileAttrs;

use strict;
use warnings;
use Readonly;

Readonly our $kFPInvisibleBit       => 0x0_001;
Readonly our $kFPMultiUserBit       => 0x0_002;
Readonly our $kFPSystemBit          => 0x0_004;  # AFP 2.0
Readonly our $kFPDAlreadyOpenBit    => 0x0_008;
Readonly our $kFPRAlreadyOpenBit    => 0x0_010;
Readonly our $kFPWriteInhibitBit    => 0x0_020;  # Was "ReadOnly" before AFP 2.0
Readonly our $kFPBackUpNeededBit    => 0x0_040;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 0x0_080;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 0x0_100;  # AFP 2.0
Readonly our $kFPCopyProtectBit     => 0x0_400;  # AFP 2.0
Readonly our $kFPSetClearBit        => 0x8_000;

1;
# vim: ts=4 et ai
