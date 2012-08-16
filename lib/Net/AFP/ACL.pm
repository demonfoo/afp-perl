package Net::AFP::ACL;

use Exporter qw(import);

our @EXPORT = qw(KAUTH_ACL_MAX_ENTRIES KAUTH_ACL_FLAGS_PRIVATE
                 KAUTH_ACL_DEFER_INHERIT KAUTH_ACL_NO_INHERIT
                 KAUTH_ACE_KINDMASK KAUTH_ACE_PERMIT KAUTH_ACE_DENY
                 KAUTH_ACE_AUDIT KAUTH_ACE_ALARM KAUTH_ACE_INHERITED
                 KAUTH_ACE_FILE_INHERIT KAUTH_ACE_DIRECTORY_INHERIT
                 KAUTH_ACE_LIMIT_INHERIT KAUTH_ACE_ONLY_INHERIT
                 KAUTH_ACE_SUCCESS KAUTH_ACE_FAILURE
                 KAUTH_ACE_INHERIT_CONTROL_FLAGS KAUTH_VNODE_READ_DATA
                 KAUTH_VNODE_LIST_DIRECTORY KAUTH_VNODE_WRITE_DATA
                 KAUTH_VNODE_ADD_FILE KAUTH_VNODE_EXECUTE KAUTH_VNODE_SEARCH
                 KAUTH_VNODE_DELETE KAUTH_VNODE_APPEND_DATA
                 KAUTH_VNODE_ADD_SUBDIRECTORY KAUTH_VNODE_DELETE_CHILD
                 KAUTH_VNODE_READ_ATTRIBUTES KAUTH_VNODE_WRITE_ATTRIBUTES
                 KAUTH_VNODE_READ_EXTATTRIBUTES
                 KAUTH_VNODE_WRITE_EXTATTRIBUTES KAUTH_VNODE_READ_SECURITY
                 KAUTH_VNODE_WRITE_SECURITY KAUTH_VNODE_TAKE_OWNERSHIP
                 KAUTH_VNODE_CHANGE_OWNER KAUTH_VNODE_SYNCHRONIZE
                 KAUTH_VNODE_GENERIC_ALL KAUTH_VNODE_GENERIC_EXECUTE
                 KAUTH_VNODE_GENERIC_WRITE KAUTH_VNODE_GENERIC_READ
                 KAUTH_VNODE_LINKTARGET KAUTH_VNODE_CHECKIMMUTABLE
                 KAUTH_VNODE_ACCESS KAUTH_VNODE_NOIMMUTABLE
                 KAUTH_VNODE_SEARCHBYANYONE KAUTH_VNODE_GENERIC_READ_BITS
                 KAUTH_VNODE_GENERIC_WRITE_BITS
                 KAUTH_VNODE_GENERIC_EXECUTE_BITS
                 KAUTH_VNODE_GENERIC_ALL_BITS KAUTH_VNODE_WRITE_RIGHTS
                 kFileSec_UUID kFileSec_GRPUUID kFileSec_ACL
                 kFileSec_REMOVEACL kFileSec_Inherit);

# kauth.h says this should be increased. maybe it even will be someday.
use constant KAUTH_ACL_MAX_ENTRIES          => 128;

# for acl_flags
use constant KAUTH_ACL_FLAGS_PRIVATE        => 0xffff;
use constant KAUTH_ACL_DEFER_INHERIT        => (1<<16);
use constant KAUTH_ACL_NO_INHERIT           => (1<<17);

# for ace_flags
use constant KAUTH_ACE_KINDMASK             => 0xf;
use constant KAUTH_ACE_PERMIT               => 1;
use constant KAUTH_ACE_DENY                 => 2;
use constant KAUTH_ACE_AUDIT                => 3;       # not implemented
use constant KAUTH_ACE_ALARM                => 4;       # not implemented
use constant KAUTH_ACE_INHERITED            => (1<<4);
use constant KAUTH_ACE_FILE_INHERIT         => (1<<5);
use constant KAUTH_ACE_DIRECTORY_INHERIT    => (1<<6);
use constant KAUTH_ACE_LIMIT_INHERIT        => (1<<7);
use constant KAUTH_ACE_ONLY_INHERIT         => (1<<8);
use constant KAUTH_ACE_SUCCESS              => (1<<9);  # not implemented
use constant KAUTH_ACE_FAILURE              => (1<<10); # not implemented
use constant KAUTH_ACE_INHERIT_CONTROL_FLAGS =>
        (KAUTH_ACE_FILE_INHERIT |
         KAUTH_ACE_DIRECTORY_INHERIT |
         KAUTH_ACE_LIMIT_INHERIT |
         KAUTH_ACE_ONLY_INHERIT);

# for ace_rights
use constant KAUTH_ACE_GENERIC_ALL          => (1<<21);
use constant KAUTH_ACE_GENERIC_EXECUTE      => (1<<22);
use constant KAUTH_ACE_GENERIC_WRITE        => (1<<23);
use constant KAUTH_ACE_GENERIC_READ         => (1<<24);

use constant KAUTH_VNODE_READ_DATA          => (1<<1);
use constant KAUTH_VNODE_LIST_DIRECTORY     => KAUTH_VNODE_READ_DATA;
use constant KAUTH_VNODE_WRITE_DATA         => (1<<2);
use constant KAUTH_VNODE_ADD_FILE           => KAUTH_VNODE_WRITE_DATA;
use constant KAUTH_VNODE_EXECUTE            => (1<<3);
use constant KAUTH_VNODE_SEARCH             => KAUTH_VNODE_EXECUTE;
use constant KAUTH_VNODE_DELETE             => (1<<4);
use constant KAUTH_VNODE_APPEND_DATA        => (1<<5);
use constant KAUTH_VNODE_ADD_SUBDIRECTORY   => KAUTH_VNODE_APPEND_DATA;
use constant KAUTH_VNODE_DELETE_CHILD       => (1<<6);
use constant KAUTH_VNODE_READ_ATTRIBUTES    => (1<<7);
use constant KAUTH_VNODE_WRITE_ATTRIBUTES   => (1<<8);
use constant KAUTH_VNODE_READ_EXTATTRIBUTES => (1<<9);
use constant KAUTH_VNODE_WRITE_EXTATTRIBUTES => (1<<10);
use constant KAUTH_VNODE_READ_SECURITY      => (1<<11);
use constant KAUTH_VNODE_WRITE_SECURITY     => (1<<12);
use constant KAUTH_VNODE_TAKE_OWNERSHIP     => (1<<13);
# backwards compatibility only
use constant KAUTH_VNODE_CHANGE_OWNER       => KAUTH_VNODE_TAKE_OWNERSHIP;
use constant KAUTH_VNODE_SYNCHRONIZE        => (1<<20);
use constant KAUTH_VNODE_LINKTARGET         => (1<<25);
use constant KAUTH_VNODE_CHECKIMMUTABLE     => (1<<26);
use constant KAUTH_VNODE_ACCESS             => (1<<31);
use constant KAUTH_VNODE_NOIMMUTABLE        => (1<<30);
use constant KAUTH_VNODE_SEARCHBYANYONE     => (1<<29);

use constant KAUTH_VNODE_GENERIC_READ_BITS  =>
        (KAUTH_VNODE_READ_DATA |
         KAUTH_VNODE_READ_ATTRIBUTES |
         KAUTH_VNODE_READ_EXTATTRIBUTES |
         KAUTH_VNODE_READ_SECURITY);

use constant KAUTH_VNODE_GENERIC_WRITE_BITS =>
        (KAUTH_VNODE_WRITE_DATA |
         KAUTH_VNODE_APPEND_DATA |
         KAUTH_VNODE_DELETE |
         KAUTH_VNODE_DELETE_CHILD |
         KAUTH_VNODE_WRITE_ATTRIBUTES |
         KAUTH_VNODE_WRITE_EXTATTRIBUTES |
         KAUTH_VNODE_WRITE_SECURITY);

use constant KAUTH_VNODE_GENERIC_EXECUTE_BITS => KAUTH_VNODE_EXECUTE;

use constant KAUTH_VNODE_GENERIC_ALL_BITS   =>
        (KAUTH_VNODE_GENERIC_READ_BITS |
         KAUTH_VNODE_GENERIC_WRITE_BITS |
         KAUTH_VNODE_GENERIC_EXECUTE_BITS);

use constant KAUTH_VNODE_WRITE_RIGHTS       =>
        (KAUTH_VNODE_ADD_FILE |
         KAUTH_VNODE_ADD_SUBDIRECTORY |
         KAUTH_VNODE_DELETE_CHILD |
         KAUTH_VNODE_WRITE_DATA |
         KAUTH_VNODE_APPEND_DATA |
         KAUTH_VNODE_DELETE |
         KAUTH_VNODE_WRITE_ATTRIBUTES |
         KAUTH_VNODE_WRITE_EXTATTRIBUTES |
         KAUTH_VNODE_WRITE_SECURITY |
         KAUTH_VNODE_TAKE_OWNERSHIP |
         KAUTH_VNODE_LINKTARGET |
         KAUTH_VNODE_CHECKIMMUTABLE);

use constant kFileSec_UUID                  => 0x01;
use constant kFileSec_GRPUUID               => 0x02;
use constant kFileSec_ACL                   => 0x04;
use constant kFileSec_REMOVEACL             => 0x08;
use constant kFileSec_Inherit               => 0x10;

1;
