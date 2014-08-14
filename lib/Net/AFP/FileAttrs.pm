package Net::AFP::FileAttrs;

Readonly our $kFPInvisibleBit       => 0x0001;
Readonly our $kFPMultiUserBit       => 0x0002;
Readonly our $kFPSystemBit          => 0x0004;  # AFP 2.0
Readonly our $kFPDAlreadyOpenBit    => 0x0008;
Readonly our $kFPRAlreadyOpenBit    => 0x0010;
Readonly our $kFPWriteInhibitBit    => 0x0020;  # Was "ReadOnly" before AFP 2.0
Readonly our $kFPBackUpNeededBit    => 0x0040;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 0x0080;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 0x0100;  # AFP 2.0
Readonly our $kFPCopyProtectBit     => 0x0400;  # AFP 2.0
Readonly our $kFPSetClearBit        => 0x8000;

1;
# vim: ts=4 et ai
