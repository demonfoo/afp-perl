package Net::AFP::AccessRights;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kSPOwner $kRPOwner $kWPOwner $kSPGroup $kRPGroup $kWPGroup
                 $kSPOther $kRPOther $kWPOther $kSPUser $kRPUser $kWPUser
		 $kBlankAccess $kUserIsOwner);

Readonly our $kSPOwner      => 1 << 0;
Readonly our $kRPOwner      => 1 << 1;
Readonly our $kWPOwner      => 1 << 2;
Readonly our $kSPGroup      => 1 << 8;
Readonly our $kRPGroup      => 1 << 9;
Readonly our $kWPGroup      => 1 << 10;
Readonly our $kSPOther      => 1 << 16;
Readonly our $kRPOther      => 1 << 17;
Readonly our $kWPOther      => 1 << 18;
Readonly our $kSPUser       => 1 << 24;
Readonly our $kRPUser       => 1 << 25;
Readonly our $kWPUser       => 1 << 26;
Readonly our $kBlankAccess  => 1 << 28;
Readonly our $kUserIsOwner  => 1 << 31;

1;
