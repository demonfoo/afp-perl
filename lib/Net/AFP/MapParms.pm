package Net::AFP::MapParms;

use Exporter qw(import);

our @EXPORT = qw(kUserIDToName kGroupIDToName kUserIDToUTF8Name
                 kGroupIDToUTF8Name kUserUUIDToUTF8Name
                 kGroupUUIDToUTF8Name kNameToUserID kNameToGroupID
                 kUTF8NameToUserID kUTF8NameToGroupID
                 kUTF8NameToUserUUID kUTF8NameToGroupUUID);

# for FPMapID()
use constant kUserIDToName          => 1;   # AFP 2.0
use constant kGroupIDToName         => 2;   # AFP 2.0
use constant kUserIDToUTF8Name      => 3;   # AFP 3.0
use constant kGroupIDToUTF8Name     => 4;   # AFP 3.0
use constant kUserUUIDToUTF8Name    => 5;   # AFP 3.2
use constant kGroupUUIDToUTF8Name   => 6;   # AFP 3.2

# for FPMapName()
use constant kNameToUserID          => 1;   # AFP 2.0
use constant kNameToGroupID         => 2;   # AFP 2.0
use constant kUTF8NameToUserID      => 3;   # AFP 3.0
use constant kUTF8NameToGroupID     => 4;   # AFP 3.0
use constant kUTF8NameToUserUUID    => 5;   # AFP 3.2
use constant kUTF8NameToGroupUUID   => 6;   # AFP 3.2

1;
