package Net::AFP::VolAttrs;

use Exporter qw(import);

our @EXPORT = qw(kReadOnly kHasVolumePassword kSupportsFileIDs
                 kSupportsCatSearch kSupportsBlankAccessPrivs
                 kSupportsUnixPrivs kSupportsUTF8Names
                 kNoNetworkUserIDs kDefaultPrivsFromParent
                 kNoExchangeFiles kSupportsExtAttrs kSupportsACLs
                 kCaseSensitive kSupportsTMLockSteal);

use constant kReadOnly                  => 0x0001;
# This bit was added as of AFP v2.1; volume passwords were supported
# previously, but this bit in the volume attribute bitmap appeared for the
# first time as part of v2.1.
use constant kHasVolumePassword         => 0x0002;  # AFP 2.1
# This bit was added, along with the FPCreateID, FPDeleteID, FPResolveID,
# and FPExchangeFiles operations, as of AFP v2.1.
use constant kSupportsFileIDs           => 0x0004;  # AFP 2.1
# This bit was also added, along with FPCatSearch, as of AFP v2.1.
use constant kSupportsCatSearch         => 0x0008;  # AFP 2.1
# This bit was also added as of AFP v2.1. This was added to support new
# features of the HFS filesystem. It can only be used with FPOpenVol()
# as of AFP 2.2, however.
use constant kSupportsBlankAccessPrivs  => 0x0010;  # AFP 2.1
use constant kSupportsUnixPrivs         => 0x0020;  # AFP 3.0
use constant kSupportsUTF8Names         => 0x0040;  # AFP 3.0
use constant kNoNetworkUserIDs          => 0x0080;  # AFP 3.1
use constant kDefaultPrivsFromParent    => 0x0100;  # AFP 3.1+ (10.3)
use constant kNoExchangeFiles           => 0x0200;  # AFP 3.2
use constant kSupportsExtAttrs          => 0x0400;  # AFP 3.2
use constant kSupportsACLs              => 0x0800;  # AFP 3.2
use constant kCaseSensitive             => 0x1000;  # AFP 3.2+ (10.5)
use constant kSupportsTMLockSteal       => 0x2000;  # AFP 3.2+ (10.5)

1;
# vim: ts=4
