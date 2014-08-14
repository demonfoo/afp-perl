package Net::AFP::DirAttrs;

use Readonly;

Readonly our $kFPInvisibleBit       => 0x0001;
Readonly our $kAttrIsExpFolderBit   => 0x0002;  # AFP 2.1
Readonly our $kFPSystemBit          => 0x0004;  # AFP 2.0
Readonly our $kAttrMountedBit       => 0x0008;  # AFP 2.1
Readonly our $kAttrInExpFolderBit   => 0x0010;  # AFP 2.1
Readonly our $kFPBackUpNeededBit    => 0x0040;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 0x0080;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 0x0100;  # AFP 2.0
Readonly our $kFPSetClearBit        => 0x8000;

1;
# vim: ts=4 et ai
