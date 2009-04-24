package Net::AFP::VolAttrs;

use constant kReadOnly					=> 0x0001;
# This bit was added as of AFP v2.1; volume passwords were supported
# previously, but this bit in the volume attribute bitmap appeared for the
# first time as part of v2.1.
use constant kHasVolumePassword			=> 0x0002;
# This bit was added, along with the FPCreateID, FPDeleteID, FPResolveID,
# and FPExchangeFiles operations, as of AFP v2.1.
use constant kSupportsFileIDs			=> 0x0004;
# This bit was also added, along with FPCatSearch, as of AFP v2.1.
use constant kSupportsCatSearch			=> 0x0008;
# This bit was also added as of AFP v2.1. This was added to support new
# features of the HFS filesystem.
use constant kSupportsBlankAccessPrivs	=> 0x0010;
use constant kSupportsUnixPrivs			=> 0x0020;
use constant kSupportsUTF8Names			=> 0x0040;
use constant kNoNetworkUserIDs			=> 0x0080;
use constant kDefaultPrivsFromParent	=> 0x0100;
use constant kNoExchangeFiles			=> 0x0200;
use constant kSupportsExtAttrs			=> 0x0400;
use constant kSupportsACLs				=> 0x0800;

1;
# vim: ts=4
