package Net::AFP::DirAttrs;

use strict;
use warnings;
use Readonly;

Readonly our $kFPInvisibleBit       => 0x0_001;
Readonly our $kAttrIsExpFolderBit   => 0x0_002;  # AFP 2.1
Readonly our $kFPSystemBit          => 0x0_004;  # AFP 2.0
Readonly our $kAttrMountedBit       => 0x0_008;  # AFP 2.1
Readonly our $kAttrInExpFolderBit   => 0x0_010;  # AFP 2.1
Readonly our $kFPBackUpNeededBit    => 0x0_040;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 0x0_080;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 0x0_100;  # AFP 2.0
Readonly our $kFPSetClearBit        => 0x8_000;

1;
# vim: ts=4 et ai
