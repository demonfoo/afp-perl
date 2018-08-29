package Net::AFP::SrvParms;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kSupportsCopyFile $kSupportsChgPwd $kDontAllowSavePwd
                 $kSupportsSrvrMsg $kSrvrSig $kSupportsTCP $kSupportsSrvrNotify
                 $kSupportsReconnect $kSupportsDirServices
                 $kSupportsUTF8SrvrName $kSupportsUUIDs $kSupportsExtSleep
                 $kSupportsSuperClient);

Readonly our $kSupportsCopyFile     => 0x0_001;
Readonly our $kSupportsChgPwd       => 0x0_002;
Readonly our $kDontAllowSavePwd     => 0x0_004;  # AFP 2.1
Readonly our $kSupportsSrvrMsg      => 0x0_008;  # AFP 2.1
Readonly our $kSrvrSig              => 0x0_010;  # AFP 2.2
Readonly our $kSupportsTCP          => 0x0_020;  # AFP 2.2
Readonly our $kSupportsSrvrNotify   => 0x0_040;  # AFP 2.2
Readonly our $kSupportsReconnect    => 0x0_080;  # AFP 3.0
Readonly our $kSupportsDirServices  => 0x0_100;  # AFP 3.0
Readonly our $kSupportsUTF8SrvrName => 0x0_200;  # AFP 3.2
Readonly our $kSupportsUUIDs        => 0x0_400;  # AFP 3.2
Readonly our $kSupportsExtSleep     => 0x0_800;  # AFP 3.2+ (10.5)
Readonly our $kSupportsSuperClient  => 0x8_000;

1;
# vim: ts=4
