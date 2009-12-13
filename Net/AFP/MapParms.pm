package Net::AFP::MapParms;

use Exporter qw(import);

our @EXPORT = qw(kUserIDToName kGroupIDToName kUserIDToUTF8Name
				 kGroupIDToUTF8Name kUserUUIDToUTF8Name
				 kGroupUUIDToUTF8Name kNameToUserID kNameToGroupID
				 kUTF8NameToUserID kUTF8NameToGroupID
				 kUTF8NameToUserUUID kUTF8NameToGroupUUID);

# for FPMapID()
use constant kUserIDToName			=> 1;
use constant kGroupIDToName			=> 2;
use constant kUserIDToUTF8Name		=> 3;
use constant kGroupIDToUTF8Name		=> 4;
use constant kUserUUIDToUTF8Name	=> 5;
use constant kGroupUUIDToUTF8Name	=> 6;

# for FPMapName()
use constant kNameToUserID			=> 1;
use constant kNameToGroupID			=> 2;
use constant kUTF8NameToUserID		=> 3;
use constant kUTF8NameToGroupID		=> 4;
use constant kUTF8NameToUserUUID	=> 5;
use constant kUTF8NameToGroupUUID	=> 6;

1;
