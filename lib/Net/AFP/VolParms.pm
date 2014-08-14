package Net::AFP::VolParms;

use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPVolAttributeBit $kFPVolSignatureBit $kFPVolCreateDateBit
                 $kFPVolModDateBit $kFPVolBackupDateBit $kFPVolIDBit
                 $kFPVolBytesFreeBit $kFPVolBytesTotalBit $kFPVolNameBit
                 $kFPVolExtBytesFreeBit $kFPVolExtBytesTotalBit
                 $kFPVolBlockSizeBit $kFPBadVolBitmap $kFPBadVolPre222Bitmap);

Readonly our $kFPVolAttributeBit        => 0x0001;
Readonly our $kFPVolSignatureBit        => 0x0002;
Readonly our $kFPVolCreateDateBit       => 0x0004;
Readonly our $kFPVolModDateBit          => 0x0008;
Readonly our $kFPVolBackupDateBit       => 0x0010;
Readonly our $kFPVolIDBit               => 0x0020;
Readonly our $kFPVolBytesFreeBit        => 0x0040;
Readonly our $kFPVolBytesTotalBit       => 0x0080;
Readonly our $kFPVolNameBit             => 0x0100;
Readonly our $kFPVolExtBytesFreeBit     => 0x0200;  # AFP 2.2
Readonly our $kFPVolExtBytesTotalBit    => 0x0400;  # AFP 2.2
Readonly our $kFPVolBlockSizeBit        => 0x0800;  # AFP 2.2
Readonly our $kFPBadVolBitmap           => 0xF000;
Readonly our $kFPBadVolPre222Bitmap     => 0xFE00;

1;
# vim: ts=4
