package Net::AFP::DirParms;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                 $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                 $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                 $kFPOffspringCountBit $kFPOwnerIDBit $kFPGroupIDBit
                 $kFPAccessRightsBit $kFPProDOSInfoBit $kFPUTF8NameBit
                 $kFPUnixPrivsBit $kFPUUID);
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
Readonly our $kFPOffspringCountBit  => 1 << 9;
Readonly our $kFPOwnerIDBit         => 1 << 10;
Readonly our $kFPGroupIDBit         => 1 << 11;
Readonly our $kFPAccessRightsBit    => 1 << 12;
Readonly our $kFPProDOSInfoBit      => 1 << 13; # AFP <= 2.2
Readonly our $kFPUTF8NameBit        => 1 << 13; # AFP >= 3.0
Readonly our $kFPUnixPrivsBit       => 1 << 15; # AFP >= 3.0
Readonly our $kFPUUID               => 1 << 16; # AFP >= 3.0

1;
# vim: ts=4
