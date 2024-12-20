package Net::AFP::DirAttrs;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPInvisibleBit $kAttrIsExpFolderBit $kSystemBit
                 $kAttrMountedBit $kAttrInExpFolderBit
                 $kFPBackUpNeededBit $kFPRenameInhibitBit
                 $kFPDeleteInhibitBit $kFPSetClearBit);
our %EXPORT_TAGS = (
    common => [qw($kFPInvisibleBit $kSystemBit $kFPBackUpNeededBit
                  $kRenameInhibitBit $kFPDeleteInhibitBit $kFPSetClearBit)],
);

Readonly our $kFPInvisibleBit       => 1 << 0;
Readonly our $kAttrIsExpFolderBit   => 1 << 1;  # AFP 2.1
Readonly our $kFPSystemBit          => 1 << 2;  # AFP 2.0
Readonly our $kAttrMountedBit       => 1 << 3;  # AFP 2.1
Readonly our $kAttrInExpFolderBit   => 1 << 4;  # AFP 2.1
Readonly our $kFPBackUpNeededBit    => 1 << 6;  # AFP 2.0
Readonly our $kFPRenameInhibitBit   => 1 << 7;  # AFP 2.0
Readonly our $kFPDeleteInhibitBit   => 1 << 8;  # AFP 2.0
Readonly our $kFPSetClearBit        => 1 << 15;

1;
# vim: ts=4 et ai
