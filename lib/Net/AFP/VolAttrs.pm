package Net::AFP::VolAttrs;

use Exporter qw(import);

our @EXPORT = qw(kReadOnly kHasVolumePassword kSupportsFileIDs
				 kSupportsCatSearch kSupportsBlankAccessPrivs
				 kSupportsUnixPrivs kSupportsUTF8Names
				 kNoNetworkUserIDs kDefaultPrivsFromParent
				 kNoExchangeFiles kSupportsExtAttrs kSupportsACLs
				 kCaseSensitive kSupportsTMLockSteal);

=head1 NAME

Net::AFP::VolAttrs - Volume attribute flags

=head1 DESCRIPTION

=over

=item kReadOnly

If set, the volume is available for reading only.

=cut
use constant kReadOnly					=> 0x0001;
=item kHasVolumePassword

If set, the volume has a volume password. Volume passwords were supported
in prior versions of AFP; now the volume attributes reflect this
information. This bit is the same as the C<HasPassword> bit returned for
each volume by L<Net::AFP/FPGetSrvrParms>.

=cut
# This bit was added as of AFP v2.1; volume passwords were supported
# previously, but this bit in the volume attribute bitmap appeared for the
# first time as part of v2.1.
use constant kHasVolumePassword			=> 0x0002;
=item kSupportsFileIDs

If set, the volume supports file IDs. In general, if file IDs are
supported on one volume, they are supported on all volumes, but this
bit allows the server to be more selective, if necessary.

=cut
# This bit was added, along with the FPCreateID, FPDeleteID, FPResolveID,
# and FPExchangeFiles operations, as of AFP v2.1.
use constant kSupportsFileIDs			=> 0x0004;
=item kSupportsCatSearch

If set, the volume supports the L<Net::AFP/FPCatSearch> and
L<Net::AFP/FPCatSearchExt> commands. Support for L<Net::AFP/FPCatSearch> and
L<Net::AFP/FPCatSearchExt> is optional. This bit allows the
server to make this capability available on a per-volume basis.

=cut
# This bit was also added, along with FPCatSearch, as of AFP v2.1.
use constant kSupportsCatSearch			=> 0x0008;
=item kFPSupportsBlankAccesPrivs

If set, the volume has a Supports Blank Access Privileges bit that, when
set for a directory, causes the directory to inherit its access
privileges from its parent directory.

=cut
# This bit was also added as of AFP v2.1. This was added to support new
# features of the HFS filesystem.
use constant kSupportsBlankAccessPrivs	=> 0x0010;
=item kSupportsUnixPrivs

If set, the volume supports UNIX privileges.

=cut
use constant kSupportsUnixPrivs			=> 0x0020;
=item kSupportsUTF8Names

If set, the volume supports UTF-8-encoded user names, group names, and
pathnames.

=cut
use constant kSupportsUTF8Names			=> 0x0040;
=item kNoNetworkUserIDs

If set, always map UNIX user IDs, group IDs and permissions to
traditional User IDs, Group IDs and permissions. If not set, after
logging into the server, an AFP client running on a UNIX-based machine
should call C<getuid()> to get the user's local user ID and send an
L<Net::AFP/FPGetUserInfo> command to get the user's user ID
from the server. If the user IDs match, the AFP client should call
C<getpwuid()> to get the user's local user name, which is returned in
the C<pw_name> field, and send an L<Net::AFP/FPMapID>
command to get the user's user name from the server. If the user names
match, the AFP client assumes both machines are operating from a common
user directory, and displays UNIX permissions without mapping them.
Showing UNIX user IDs, group IDs, and permissions is useful for home
directory servers and other servers participating in a network user
database. If the user IDs or user names do not match, or if the AFP
client is not running on a UNIX-based machine, the AFP client should
map UNIX user IDs, group IDs and permissions to traditional User IDs,
Group IDs and permissions. This default behavior can be changed by
settings on the server. The server can be forced to always set or to
never set the L</kNoNetworkUserIDs> bit.

=cut
use constant kNoNetworkUserIDs			=> 0x0080;
=item kDefaultPrivsFromParent

If set, directories inherit default privileges from the parent directory.

=cut
use constant kDefaultPrivsFromParent	=> 0x0100;
=item kNoExchangeFiles

If set, exchange files is not supported.

=cut
use constant kNoExchangeFiles			=> 0x0200;
=item kSupportsExtAttrs

If set, the volume supports extended attributes.

=cut
use constant kSupportsExtAttrs			=> 0x0400;
=item kSupportsACLs

If set, the volume supports access control lists (ACLs).

=cut
use constant kSupportsACLs				=> 0x0800;
=item kCaseSensitive

If set, the volume supports case-sensitive filenames.

=cut
# New with AFP 3.3.
use constant kCaseSensitive				=> 0x1000;
=item kSupportsTMLockSteal

If set, volume supports Time Machine lock stealing.

=cut
# New with AFP 3.3.
use constant kSupportsTMLockSteal		=> 0x2000;

1;
# vim: ts=4
