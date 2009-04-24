package Net::AFP::VolParms;

use constant kFPVolAttributeBit		=> 0x0001;
use constant kFPVolSignatureBit		=> 0x0002;
use constant kFPVolCreateDateBit	=> 0x0004;
use constant kFPVolModDateBit		=> 0x0008;
use constant kFPVolBackupDateBit	=> 0x0010;
use constant kFPVolIDBit			=> 0x0020;
use constant kFPVolBytesFreeBit		=> 0x0040;
use constant kFPVolBytesTotalBit	=> 0x0080;
use constant kFPVolNameBit			=> 0x0100;
use constant kFPVolExtBytesFreeBit	=> 0x0200;
use constant kFPVolExtBytesTotalBit	=> 0x0400;
use constant kFPVolBlockSizeBit		=> 0x0800;
use constant kFPBadVolBitmap		=> 0xF000;
use constant kFPBadVolPre222Bitmap	=> 0xFE00;

1;
# vim: ts=4
