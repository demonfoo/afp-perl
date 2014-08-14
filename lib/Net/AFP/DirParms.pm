package Net::AFP::DirParms;

use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                 $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                 $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                 $kFPOffspringCountBit $kFPOwnerIDBit $kFPGroupIDBit
                 $kFPAccessRightsBit $kFPProDOSInfoBit $kFPUTF8NameBit
                 $kFPUnixPrivsBit $kFPUUID);
our %EXPORT_TAGS = (
    'common' => [qw($kFPAttributeBit $kFPParentDirIDBit $kFPCreateDateBit
                    $kFPModDateBit $kFPBackupDateBit $kFPFinderInfoBit
                    $kFPLongNameBit $kFPShortNameBit $kFPNodeIDBit
                    $kFPUTF8NameBit $kFPUnixPrivsBit)],
);

Readonly our $kFPAttributeBit       => 0x00001;
Readonly our $kFPParentDirIDBit     => 0x00002;
Readonly our $kFPCreateDateBit      => 0x00004;
Readonly our $kFPModDateBit         => 0x00008;
Readonly our $kFPBackupDateBit      => 0x00010;
Readonly our $kFPFinderInfoBit      => 0x00020;
Readonly our $kFPLongNameBit        => 0x00040;
Readonly our $kFPShortNameBit       => 0x00080;
Readonly our $kFPNodeIDBit          => 0x00100;
Readonly our $kFPOffspringCountBit  => 0x00200;
Readonly our $kFPOwnerIDBit         => 0x00400;
Readonly our $kFPGroupIDBit         => 0x00800;
Readonly our $kFPAccessRightsBit    => 0x01000;
Readonly our $kFPProDOSInfoBit      => 0x02000; # AFP <= 2.2
Readonly our $kFPUTF8NameBit        => 0x02000; # AFP >= 3.0
Readonly our $kFPUnixPrivsBit       => 0x08000; # AFP >= 3.0
Readonly our $kFPUUID               => 0x10000; # AFP >= 3.0

1;
# vim: ts=4
