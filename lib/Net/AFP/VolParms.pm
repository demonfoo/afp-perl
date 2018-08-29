package Net::AFP::VolParms;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPVolAttributeBit $kFPVolSignatureBit $kFPVolCreateDateBit
                 $kFPVolModDateBit $kFPVolBackupDateBit $kFPVolIDBit
                 $kFPVolBytesFreeBit $kFPVolBytesTotalBit $kFPVolNameBit
                 $kFPVolExtBytesFreeBit $kFPVolExtBytesTotalBit
                 $kFPVolBlockSizeBit $kFPBadVolBitmap $kFPBadVolPre222Bitmap);

Readonly our $kFPVolAttributeBit        => 0x0_001;
Readonly our $kFPVolSignatureBit        => 0x0_002;
Readonly our $kFPVolCreateDateBit       => 0x0_004;
Readonly our $kFPVolModDateBit          => 0x0_008;
Readonly our $kFPVolBackupDateBit       => 0x0_010;
Readonly our $kFPVolIDBit               => 0x0_020;
Readonly our $kFPVolBytesFreeBit        => 0x0_040;
Readonly our $kFPVolBytesTotalBit       => 0x0_080;
Readonly our $kFPVolNameBit             => 0x0_100;
Readonly our $kFPVolExtBytesFreeBit     => 0x0_200;  # AFP 2.2
Readonly our $kFPVolExtBytesTotalBit    => 0x0_400;  # AFP 2.2
Readonly our $kFPVolBlockSizeBit        => 0x0_800;  # AFP 2.2
Readonly our $kFPBadVolBitmap           => 0xF_000;
Readonly our $kFPBadVolPre222Bitmap     => 0xF_E00;

1;
# vim: ts=4
