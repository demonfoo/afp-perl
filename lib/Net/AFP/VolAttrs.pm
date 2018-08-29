package Net::AFP::VolAttrs;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kReadOnly $kHasVolumePassword $kSupportsFileIDs
                 $kSupportsCatSearch $kSupportsBlankAccessPrivs
                 $kSupportsUnixPrivs $kSupportsUTF8Names
                 $kNoNetworkUserIDs $kDefaultPrivsFromParent
                 $kNoExchangeFiles $kSupportsExtAttrs $kSupportsACLs
                 $kCaseSensitive $kSupportsTMLockSteal);

Readonly our $kReadOnly                 => 0x0_001;
# This bit was added as of AFP v2.1; volume passwords were supported
# previously, but this bit in the volume attribute bitmap appeared for the
# first time as part of v2.1.
Readonly our $kHasVolumePassword        => 0x0_002;  # AFP 2.1
# This bit was added, along with the FPCreateID, FPDeleteID, FPResolveID,
# and FPExchangeFiles operations, as of AFP v2.1.
Readonly our $kSupportsFileIDs          => 0x0_004;  # AFP 2.1
# This bit was also added, along with FPCatSearch, as of AFP v2.1.
Readonly our $kSupportsCatSearch        => 0x0_008;  # AFP 2.1
# This bit was also added as of AFP v2.1. This was added to support new
# features of the HFS filesystem. It can only be used with FPOpenVol()
# as of AFP 2.2, however.
Readonly our $kSupportsBlankAccessPrivs => 0x0_010;  # AFP 2.1
Readonly our $kSupportsUnixPrivs        => 0x0_020;  # AFP 3.0
Readonly our $kSupportsUTF8Names        => 0x0_040;  # AFP 3.0
Readonly our $kNoNetworkUserIDs         => 0x0_080;  # AFP 3.1
Readonly our $kDefaultPrivsFromParent   => 0x0_100;  # AFP 3.1+ (10.3)
Readonly our $kNoExchangeFiles          => 0x0_200;  # AFP 3.2
Readonly our $kSupportsExtAttrs         => 0x0_400;  # AFP 3.2
Readonly our $kSupportsACLs             => 0x0_800;  # AFP 3.2
Readonly our $kCaseSensitive            => 0x1_000;  # AFP 3.2+ (10.5)
Readonly our $kSupportsTMLockSteal      => 0x2_000;  # AFP 3.2+ (10.5)

1;
# vim: ts=4
