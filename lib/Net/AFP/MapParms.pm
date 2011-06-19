package Net::AFP::MapParms;

use Exporter qw(import);

our @EXPORT = qw(kUserIDToName kGroupIDToName kUserIDToUTF8Name
                 kGroupIDToUTF8Name kUserUUIDToUTF8Name
                 kGroupUUIDToUTF8Name kNameToUserID kNameToGroupID
                 kUTF8NameToUserID kUTF8NameToGroupID
                 kUTF8NameToUserUUID kUTF8NameToGroupUUID);

=head1 NAME

Net::AFP::MapParms - mode parameters for FPMapID/FPMapName operations

=head1 DESCRIPTION

The following are constants to be passed as the C<$SubFunction> parameter
to the L<Net::AFP/FPMapID> call.

=over

=item kUserIDToName

Used to map a numeric User ID to the corresponding user name. The returned
string will be encoded as MacRoman.

=cut
use constant kUserIDToName          => 1;   # AFP 2.0
=item kGroupIDToName

Used to map a numeric Group ID to the corresponding group name. The returned
string will be encoded as MacRoman.

=cut
use constant kGroupIDToName         => 2;   # AFP 2.0
=item kUserIDToUTF8Name

Used to map a numeric User ID to the corresponding user name. The returned
string will be encoded as decomposed UTF-8.

=cut
use constant kUserIDToUTF8Name      => 3;   # AFP 3.0
=item kGroupIDToUTF8Name

Used to map a numeric Group ID to the corresponding group name. The returned
string will be encoded as decomposed UTF-8.

=cut
use constant kGroupIDToUTF8Name     => 4;   # AFP 3.0
=item kUserUUIDToUTF8Name

Used to map a UUID to the corresponding user name. Contrary to the naming,
this works for both user and group UUIDs, as both exist within a common
namespace. The returned structure will containg a string which will be
encoded as decomposed UTF-8.

The structure is as follows:

   {
     'Bitmap'     => [ 1 for UID, 2 for GID ],
     'NumericID'  => [ numeric UID or GID ],
     'UTF8Name'   => [ user/group name ],
   }

=cut
use constant kUserUUIDToUTF8Name    => 5;   # AFP 3.2
=item kGroupUUIDToUTF8Name

Used to map a UUID to the corresponding group name. Contrary to the naming,
this works for both user and group UUIDs, as both exist within a common
namespace. The returned structure will containg a string which will be
encoded as decomposed UTF-8.

The structure is as follows:

   {
     'Bitmap'     => [ 1 for UID, 2 for GID ],
     'NumericID'  => [ numeric UID or GID ],
     'UTF8Name'   => [ user/group name ],
   }

=cut
use constant kGroupUUIDToUTF8Name   => 6;   # AFP 3.2
=back

The following are constants to be passed as the C<$SubFunction> parameter
to the L<Net::AFP/FPMapName> call.

=over

=item kNameToUserID

Used to map a user name to the corresponding numeric User ID. The user name
passed will be encoded as MacRoman.

=cut
use constant kNameToUserID          => 1;   # AFP 2.0
=item kNameToGroupID

Used to map a group name to the corresponding numeric Group ID. The group
name passed will be encoded as MacRoman.

=cut
use constant kNameToGroupID         => 2;   # AFP 2.0
=item kUTF8NameToUserID

Used to map a user name to the corresponding numeric User ID. The user name
passed will be encoded as UTF-8.

=cut
use constant kUTF8NameToUserID      => 3;   # AFP 3.0
=item kUTF8NameToGroupID

Used to map a group name to the corresponding numeric Group ID. The group
name passed will be encoded as UTF-8.

=cut
use constant kUTF8NameToGroupID     => 4;   # AFP 3.0
=item kUTF8NameToUserUUID

Used to map a user name to the corresponding numeric User UUID. The user
name passed will be encoded as UTF-8.

=cut
use constant kUTF8NameToUserUUID    => 5;   # AFP 3.2
=item kUTF8NameToGroupUUID

Used to map a group name to the corresponding numeric Group UUID. The group
name passed will be encoded as UTF-8.

=cut
use constant kUTF8NameToGroupUUID   => 6;   # AFP 3.2
=back

=head1 AUTHOR

Derrik Pates <demon@now.ai>

=head1 SEE ALSO

C<Net::AFP>

=cut

1;
