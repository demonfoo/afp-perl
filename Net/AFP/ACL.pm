package Net::AFP::ACL;

use Exporter qw(import);

our @EXPORT = qw(KAUTH_ACL_FLAGS_PRIVATE KAUTH_ACL_DEFER_INHERIT
				 KAUTH_ACL_NO_INHERIT KAUTH_ACE_KINDMASK
				 KAUTH_ACE_PERMIT KAUTH_ACE_DENY KAUTH_ACE_AUDIT
				 KAUTH_ACE_ALARM KAUTH_ACE_INHERITED KAUTH_ACE_FILE_INHERIT
				 KAUTH_ACE_DIRECTORY_INHERIT KAUTH_ACE_LIMIT_INHERIT
				 KAUTH_ACE_ONLY_INHERIT KAUTH_ACE_SUCCESS
				 KAUTH_ACE_FAILURE KAUTH_ACE_INHERIT_CONTROL_FLAGS
				 KAUTH_ACE_GENERIC_ALL KAUTH_ACE_GENERIC_EXECUTE
				 KAUTH_ACE_GENERIC_READ KAUTH_ACE_GENERIC_WRITE
				 KAUTH_VNODE_READ_DATA KAUTH_VNODE_LIST_DIRECTORY
				 KAUTH_VNODE_WRITE_DATA KAUTH_VNODE_ADD_FILE
				 KAUTH_VNODE_EXECUTE KAUTH_VNODE_SEARCH KAUTH_VNODE_DELETE
				 KAUTH_VNODE_APPEND_DATA KAUTH_VNODE_ADD_SUBDIRECTORY
				 KAUTH_VNODE_DELETE_CHILD KAUTH_VNODE_READ_ATTRIBUTES
				 KAUTH_VNODE_WRITE_ATTRIBUTES KAUTH_VNODE_READ_EXTATTRIBUTES
				 KAUTH_VNODE_WRITE_EXTATTRIBUTES KAUTH_VNODE_READ_SECURITY
				 KAUTH_VNODE_WRITE_SECURITY KAUTH_VNODE_CHANGE_OWNER
				 KAUTH_VNODE_SYNCHRONIZE KAUTH_VNODE_GENERIC_ALL
				 KAUTH_VNODE_GENERIC_EXECUTE KAUTH_VNODE_GENERIC_WRITE
				 KAUTH_VNODE_GENERIC_READ KAUTH_VNODE_LINKTARGET
				 KAUTH_VNODE_CHECKIMMUTABLE KAUTH_VNODE_ACCESS
				 KAUTH_VNODE_NOIMMUTABLE KAUTH_VNODE_SEARCHBYANYONE
				 kFileSec_UUID kFileSec_GRPUUID kFileSec_ACL
				 kFileSec_REMOVEACL kFileSec_Inherit);

=head1 NAME

Net::AFP::ACL - ACL related flags and values

=head1 DESCRIPTION

=cut

# for acl_flags
use constant KAUTH_ACL_FLAGS_PRIVATE		=> 0xffff;
use constant KAUTH_ACL_DEFER_INHERIT		=> (1<<16);
use constant KAUTH_ACL_NO_INHERIT			=> (1<<17);

# for ace_flags
use constant KAUTH_ACE_KINDMASK				=> 0xf;
use constant KAUTH_ACE_PERMIT				=> 1;
use constant KAUTH_ACE_DENY					=> 2;
use constant KAUTH_ACE_AUDIT				=> 3;		# not implemented		
use constant KAUTH_ACE_ALARM				=> 4;		# not implemented
use constant KAUTH_ACE_INHERITED			=> (1<<4);
use constant KAUTH_ACE_FILE_INHERIT			=> (1<<5);
use constant KAUTH_ACE_DIRECTORY_INHERIT	=> (1<<6);
use constant KAUTH_ACE_LIMIT_INHERIT		=> (1<<7);
use constant KAUTH_ACE_ONLY_INHERIT			=> (1<<8);
use constant KAUTH_ACE_SUCCESS				=> (1<<9);	# not implemented
use constant KAUTH_ACE_FAILURE				=> (1<<10);	# not implemented
use constant KAUTH_ACE_INHERIT_CONTROL_FLAGS =>
		(KAUTH_ACE_FILE_INHERIT |
		KAUTH_ACE_DIRECTORY_INHERIT |
		KAUTH_ACE_LIMIT_INHERIT |
		KAUTH_ACE_ONLY_INHERIT);

# for ace_rights
use constant KAUTH_ACE_GENERIC_ALL			=> (1<<21);
use constant KAUTH_ACE_GENERIC_EXECUTE		=> (1<<22);
use constant KAUTH_ACE_GENERIC_WRITE		=> (1<<23);
use constant KAUTH_ACE_GENERIC_READ			=> (1<<24);

=head2 ACL Access Rights

Access rights bit definitions.

=over

=item KAUTH_VNODE_READ_DATA

For a file, the right to read a file's data; for a directory, the right
to list the contents of a directory.

=cut
use constant KAUTH_VNODE_READ_DATA			=> (1<<1);
=item KAUTH_VNODE_LIST_DIRECTORY

For a directory, the same as C<KAUTH_VNODE_READ_DATA>, which is the
right to list the contents of a directory.

=cut
use constant KAUTH_VNODE_LIST_DIRECTORY		=> KAUTH_VNODE_READ_DATA;
=item KAUTH_VNODE_WRITE_DATA

For a file, the right to write to a file; for a directory, the right to
create a file in a directory.

=cut
use constant KAUTH_VNODE_WRITE_DATA			=> (1<<2);
=item KAUTH_VNODE_ADD_FILE

For a file, the same as KAUTH_VNODE_WRITE_DATA; the right to write to a file.

=cut
use constant KAUTH_VNODE_ADD_FILE			=> KAUTH_VNODE_WRITE_DATA;
=item KAUTH_VNODE_EXECUTE

Right to execute a program.

=cut
use constant KAUTH_VNODE_EXECUTE			=> (1<<3);
=item KAUTH_VNODE_SEARCH

Same as C<KAUTH_VNODE_EXECUTE>.

=cut
use constant KAUTH_VNODE_SEARCH				=> KAUTH_VNODE_EXECUTE;
=item KAUTH_VNODE_DELETE

Right to delete a file.

=cut
use constant KAUTH_VNODE_DELETE				=> (1<<4);
=item KAUTH_VNODE_APPEND_DATA

For a file, the right to append data to a file; for a directory, the
right to create a subdirectory in a directory.

=cut
use constant KAUTH_VNODE_APPEND_DATA		=> (1<<5);
=item KAUTH_VNODE_ADD_SUBDIRECTORY

For a directory, the same as C<KAUTH_VNODE_APPEND_DATA>, which is the
right to create a subdirectory in a directory.

=cut
use constant KAUTH_VNODE_ADD_SUBDIRECTORY	=> KAUTH_VNODE_APPEND_DATA;
=item KAUTH_VNODE_DELETE_CHILD

Right to delete a directory and all the files it contains.

=cut
use constant KAUTH_VNODE_DELETE_CHILD		=> (1<<6);
=item KAUTH_VNODE_READ_ATTRIBUTES

Right to read a file's hidden attributes, such as hidden, read-only,
system, and archive.

=cut
use constant KAUTH_VNODE_READ_ATTRIBUTES	=> (1<<7);
=item KAUTH_VNODE_WRITE_ATTRIBUTES

Right to write a file's attributes, such as hidden, read-only, system,
and archive.

=cut
use constant KAUTH_VNODE_WRITE_ATTRIBUTES	=> (1<<8);
=item KAUTH_VNODE_READ_EXTATTRIBUTES

Right to read a file or directory's extended attributes.

=cut
use constant KAUTH_VNODE_READ_EXTATTRIBUTES	=> (1<<9);
=item KAUTH_VNODE_WRITE_EXTATTRIBUTES

Right to write extended attributes.

=cut
use constant KAUTH_VNODE_WRITE_EXTATTRIBUTES => (1<<10);
=item KAUTH_VNODE_READ_SECURITY

Right to get a file or directory's access rights.

=cut
use constant KAUTH_VNODE_READ_SECURITY		=> (1<<11);
=item KAUTH_VNODE_WRITE_SECURITY

Right to set a file or directory's access rights.

=cut
use constant KAUTH_VNODE_WRITE_SECURITY		=> (1<<12);
=item KAUTH_VNODE_CHANGE_OWNER

Right to change the owner of a file or directory.

=cut
use constant KAUTH_VNODE_CHANGE_OWNER		=> (1<<13);
=item KAUTH_VNODE_SYNCHRONIZE

Right to block until the file or directory is put in the signaled
state; provided for Windows interoperability.

=cut
use constant KAUTH_VNODE_SYNCHRONIZE		=> (1<<20);
=item KAUTH_VNODE_GENERIC_ALL

Windows NT right that includes all rights specified by 
C<KAUTH_VNODE_GENERIC_EXECUTE>, C<KAUTH_VNODE_GENERIC_WRITE>, and
C<KAUTH_VNODE_GENERIC_READ>.

=cut
use constant KAUTH_VNODE_GENERIC_ALL		=> (1<<21);
=item KAUTH_VNODE_GENERIC_EXECUTE

Windows NT right that in Windows 2000 became the right to read
attributes, read permissions, traverse folders, and execute files.

=cut
use constant KAUTH_VNODE_GENERIC_EXECUTE	=> (1<<22);
=item KAUTH_VNODE_GENERIC_WRITE

Windows NT right that in Windows 2000 became right to read access
rights, create a subdirectory in a directory, write data in a file,
create files in a directory, append data to a file, write attributes,
and write extended attributes.

=cut
use constant KAUTH_VNODE_GENERIC_WRITE		=> (1<<23);
=item KAUTH_VNODE_GENERIC_READ

Windows NT right that in Windows 2000 became right to list directories,
read file data, read attributes, read extended attributes, and read
access rights.

=cut
use constant KAUTH_VNODE_GENERIC_READ		=> (1<<24);
=item KAUTH_VNODE_LINKTARGET

=cut
use constant KAUTH_VNODE_LINKTARGET			=> (1<<25);
=item KAUTH_VNODE_CHECKIMMUTABLE

=cut
use constant KAUTH_VNODE_CHECKIMMUTABLE		=> (1<<26);
=item KAUTH_VNODE_ACCESS

=cut
use constant KAUTH_VNODE_ACCESS				=> (1<<31);
=item KAUTH_VNODE_NOIMMUTABLE

=cut
use constant KAUTH_VNODE_NOIMMUTABLE		=> (1<<30);
=item KAUTH_VNODE_SEARCHBYANYONE

=cut
use constant KAUTH_VNODE_SEARCHBYANYONE		=> (1<<29);
=back

=head2 Access Control List Bitmap

Bitmap for getting and setting access control lists (ACLs).

=over

=item C<kFileSec_UUID>

Set this bit to get or set a UUID.

=cut
use constant kFileSec_UUID					=> 0x01;
=item C<kFileSec_GRPUUID>

Set this bit to get or set a Group UUID.

=cut
use constant kFileSec_GRPUUID				=> 0x02;
=item C<kFileSec_ACL>

Set this bit to get or set an ACL.

=cut
use constant kFileSec_ACL					=> 0x04;
=item C<kFileSec_REMOVEACL>

Set this bit to remove an ACL. This bit is not valid when used with the
L<Net::AFP::Connection/FPGetACL> command.

=cut
use constant kFileSec_REMOVEACL				=> 0x08;
=item C<kFileSec_Inherit>

Set this bit to inherit all ACEs from the parent directory. This constant
is used only with the L<Net::AFP::Connection/FPSetACL> command.

=cut
use constant kFileSec_Inherit				=> 0x10;
=back

=cut

1;
