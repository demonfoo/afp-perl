package Net::AFP::FileAttrs;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPInvisibleBit $kFPMultiUserBit $kSystemBit
                 $kFPDAlreadyOpenBit $kFPRAlreadyOpenBit
                 $kFPWriteInhibitBit $kFPBackUpNeededBit
                 $kFPRenameInhibitBit $kFPDeleteInhibitBit
                 $kFPCopyProtectBit $kFPSetClearBit);
our %EXPORT_TAGS = (
    common => [qw($kFPInvisibleBit $kSystemBit $kFPBackUpNeededBit
                  $kRenameInhibitBit $kFPDeleteInhibitBit $kFPSetClearBit)],
);

Readonly our $kFPInvisibleBit       => 1 << 0;
Readonly our $kFPMultiUserBit       => 1 << 1;
Readonly our $kFPSystemBit          => 1 << 2;  # AFP 2.0
Readonly our $kFPDAlreadyOpenBit    => 1 << 3;
Readonly our $kFPRAlreadyOpenBit    => 1 << 4;
Readonly our $kFPWriteInhibitBit    => 1 << 5;  # Was "ReadOnly" before AFP 2.0
Readonly our $kFPBackUpNeededBit    => 1 << 6;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 1 << 7;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 1 << 8;  # AFP 2.0
Readonly our $kFPCopyProtectBit     => 1 << 10; # AFP 2.0
Readonly our $kFPSetClearBit        => 1 << 15;

1;
# vim: ts=4 et ai
