package Net::AFP::SrvParms;

use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kSupportsCopyFile $kSupportsChgPwd $kDontAllowSavePwd
                 $kSupportsSrvrMsg $kSrvrSig $kSupportsTCP $kSupportsSrvrNotify
                 $kSupportsReconnect $kSupportsDirServices
                 $kSupportsUTF8SrvrName $kSupportsUUIDs $kSupportsExtSleep
                 $kSupportsSuperClient);

Readonly our $kSupportsCopyFile     => 0x0001;
Readonly our $kSupportsChgPwd       => 0x0002;
Readonly our $kDontAllowSavePwd     => 0x0004;  # AFP 2.1
Readonly our $kSupportsSrvrMsg      => 0x0008;  # AFP 2.1
Readonly our $kSrvrSig              => 0x0010;  # AFP 2.2
Readonly our $kSupportsTCP          => 0x0020;  # AFP 2.2
Readonly our $kSupportsSrvrNotify   => 0x0040;  # AFP 2.2
Readonly our $kSupportsReconnect    => 0x0080;  # AFP 3.0
Readonly our $kSupportsDirServices  => 0x0100;  # AFP 3.0
Readonly our $kSupportsUTF8SrvrName => 0x0200;  # AFP 3.2
Readonly our $kSupportsUUIDs        => 0x0400;  # AFP 3.2
Readonly our $kSupportsExtSleep     => 0x0800;  # AFP 3.2+ (10.5)
Readonly our $kSupportsSuperClient  => 0x8000;

1;
# vim: ts=4
