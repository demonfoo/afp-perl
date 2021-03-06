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
    'common' => [qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                    $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                    $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                    $kFPUTF8NameBit $kFPUnixPrivsBit)],
);

Readonly our $kFPAttributeBit       => 0x0_001;
Readonly our $kFPParentDirIDBit     => 0x0_002;
Readonly our $kFPCreateDateBit      => 0x0_004;
Readonly our $kFPModDateBit         => 0x0_008;
Readonly our $kFPBackupDateBit      => 0x0_010;
Readonly our $kFPFinderInfoBit      => 0x0_020;
Readonly our $kFPLongNameBit        => 0x0_040;
Readonly our $kFPShortNameBit       => 0x0_080;
Readonly our $kFPNodeIDBit          => 0x0_100;
Readonly our $kFPDataForkLenBit     => 0x0_200;
Readonly our $kFPRsrcForkLenBit     => 0x0_400;
Readonly our $kFPExtDataForkLenBit  => 0x0_800; # AFP 2.3/3.0?
Readonly our $kFPLaunchLimitBit     => 0x1_000; # AFP 2.3/3.0?
Readonly our $kFPUTF8NameBit        => 0x2_000; # AFP 3.0; used to be for
                                                # ProDOS info (AFP 2.0-2.3)
Readonly our $kFPExtRsrcForkLenBit  => 0x4_000; # AFP 2.3/3.0?
Readonly our $kFPUnixPrivsBit       => 0x8_000; # AFP 3.0

1;
# vim: ts=4
