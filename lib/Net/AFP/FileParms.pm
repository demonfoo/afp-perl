package Net::AFP::FileParms;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                 $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                 $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                 $kFPDataForkLenBit $kFPRsrcForkLenBit $kFPExtDataForkLenBit
                 $kFPLaunchLimitBit $kFPUTF8NameBit $kFPExtRsrcForkLenBit
                 $kFPUnixPrivsBit);
our %EXPORT_TAGS = (
    common => [qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                  $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                  $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                  $kFPUTF8NameBit $kFPUnixPrivsBit)],
);

Readonly our $kFPAttributeBit       => 1 << 0;
Readonly our $kFPParentDirIDBit     => 1 << 1;
Readonly our $kFPCreateDateBit      => 1 << 2;
Readonly our $kFPModDateBit         => 1 << 3;
Readonly our $kFPBackupDateBit      => 1 << 4;
Readonly our $kFPFinderInfoBit      => 1 << 5;
Readonly our $kFPLongNameBit        => 1 << 6;
Readonly our $kFPShortNameBit       => 1 << 7;
Readonly our $kFPNodeIDBit          => 1 << 8;
Readonly our $kFPDataForkLenBit     => 1 << 9;
Readonly our $kFPRsrcForkLenBit     => 1 << 10;
Readonly our $kFPExtDataForkLenBit  => 1 << 11; # AFP 2.3/3.0?
Readonly our $kFPLaunchLimitBit     => 1 << 12; # AFP 2.3/3.0?
Readonly our $kFPUTF8NameBit        => 1 << 13; # AFP 3.0; used to be for
                                                # ProDOS info (AFP 2.0-2.3)
Readonly our $kFPExtRsrcForkLenBit  => 1 << 14; # AFP 2.3/3.0?
Readonly our $kFPUnixPrivsBit       => 1 << 15; # AFP 3.0

1;
# vim: ts=4
