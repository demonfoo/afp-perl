package Net::AFP::MapParms;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kUserIDToName $kGroupIDToName $kUserIDToUTF8Name
                 $kGroupIDToUTF8Name $kUserUUIDToUTF8Name
                 $kGroupUUIDToUTF8Name $kNameToUserID $kNameToGroupID
                 $kUTF8NameToUserID $kUTF8NameToGroupID
                 $kUTF8NameToUserUUID $kUTF8NameToGroupUUID);

Readonly our $kUserIDToName         => 1;   # AFP 2.0
Readonly our $kGroupIDToName        => 2;   # AFP 2.0
Readonly our $kUserIDToUTF8Name     => 3;   # AFP 3.0
Readonly our $kGroupIDToUTF8Name    => 4;   # AFP 3.0
Readonly our $kUserUUIDToUTF8Name   => 5;   # AFP 3.2
Readonly our $kGroupUUIDToUTF8Name  => 6;   # AFP 3.2

Readonly our $kNameToUserID         => 1;   # AFP 2.0
Readonly our $kNameToGroupID        => 2;   # AFP 2.0
Readonly our $kUTF8NameToUserID     => 3;   # AFP 3.0
Readonly our $kUTF8NameToGroupID    => 4;   # AFP 3.0
Readonly our $kUTF8NameToUserUUID   => 5;   # AFP 3.2
Readonly our $kUTF8NameToGroupUUID  => 6;   # AFP 3.2

1;
