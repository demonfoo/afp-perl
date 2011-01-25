package Net::AFP::Fuse;

# Declare ourselves as a derivate of Fuse::Class.
use base qw(Fuse::Class);

# imports {{{1
use strict;
use warnings;
no warnings qw(redefine);
use diagnostics;

# Tell Perl we need to be run in at least v5.8.
use v5.8;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{'__WARN__'} = \&Carp::cluck;

use Net::AFP;
use Net::AFP::Helpers;
use Net::AFP::Result;           # AFP result codes
use Net::AFP::VolAttrs;         # volume attribute definitions
use Net::AFP::VolParms;         # parameters for FPOpenVol()
use Net::AFP::Versions;         # version checking/agreement helper code
use Net::AFP::MapParms;         # mapping function operation codes
use Net::AFP::FileParms qw(:DEFAULT !:common);
use Net::AFP::DirParms;
use Net::AFP::ExtAttrs;
use Net::AFP::ACL;
use Encode;                     # handle encoding/decoding strings
use Socket;                     # for socket related constants for
                                # parent/child IPC code
use Fcntl qw(O_RDONLY O_WRONLY O_RDWR O_ACCMODE :mode);
use Data::Dumper;               # for diagnostic output when debugging is on
use Errno qw(:POSIX);           # Standard errors codes.
use Fuse qw(:xattr);            # Still need this for extended attribute
                                # related macros.

sub ENODATA { return($^O eq 'freebsd' ? &Errno::ENOATTR : &Errno::ENODATA); }

# We need Data::UUID for a portable means to get a UUID to identify
# ourselves to the AFP server for FPAccess() calls; if it's there, it's
# definitely preferred.
my $has_Data__UUID = 0;
eval { require Data::UUID; 1; } and do { $has_Data__UUID = 1; };

# How much write data can we buffer locally before flushing to the server?
use constant COALESCE_MAX       => 131072;

# What character encoding we should be pushing out to the virtual filesystem
# for paths? This is it.
use constant ENCODING           => 'utf8';

# Special magic extended attribute names to take advantage of certain
# AFP features.
use constant ACL_XATTR          => 'system.afp_acl';
use constant COMMENT_XATTR      => 'system.comment';

# }}}1

=head1 NAME

Net::AFP::Fuse - An AFP filesystem implementation in Perl

=head1 SYNOPSIS

This package is a FUSE filesystem implementation. It derives from the
Fuse::Class package, implementing the major FUSE operations as methods.

The following is a trivial use case:

    use Net::AFP::Fuse;

    my $fuse = new Net::AFP::Fuse($afp_url, $pw_cb);
    $fuse->main('mountpoint' => $mountpoint, 'mountopts' => '...');

=head1 DESCRIPTION

This package makes use of Net::AFP::TCP (and optionally, Net::AFP::Atalk)
to connect to an AFP server, and implement all the major filesystem operations
required of a FUSE filesystem.

It derives from Fuse::Class, as mentioned. This is a thin object-oriented
wrapper over the Fuse package, a set of Perl bindings for libfuse.

This module (and the modules which it depends on) implement a fairly
complete, working implementation of Apple Filing Protocol. It compares
favorably with Apple's implementation in MacOS X. It implements several
advanced features:

   * Access control lists
   * Extended attributes
   * Large files
   * Encrypted login (via Diffie-Hellman exchange)
   * UNIX ownership/permissions
   * UTF-8 filenames
   * IPv6 support, with IO::Socket::INET6

It also remains compatible with classic Mac OS; I've mounted filesystems
from MacOS 9.x, but it should work with versions even older than that, at
least in principle.

=head1 SUBROUTINES/METHODS

The main method is not overridden in this class. Most other methods are for
internal use only, or for invocation by Fuse::Class.

=over

=item new( URL, PW_CB )

=cut

sub new { # {{{1
    my ($class, $url, $pw_cb) = @_;

    my $obj = $class->SUPER::new();
    $$obj{'topDirID'} = 2;
    $$obj{'volID'} = undef;
    $$obj{'DTRefNum'} = undef;
    $$obj{'afpconn'} = undef;
    # open fork numbers for files that have been opened via afp_open()
    $$obj{'ofcache'} = {};

    my($session, %urlparms);
    my $callback = sub {
        my(%values) = @_;
        return &$pw_cb(@values{'username', 'host', 'password'});
    };
    ($session, %urlparms) = do_afp_connect($callback, $url);
    unless (ref($session) && $session->isa('Net::AFP')) {
        exit($session);
    }

    unless (defined $urlparms{'volume'}) {
        $session->close();
        croak('Unable to extract volume from AFP URL')
    }
    $$obj{'afpconn'} = $session;

    # Since AFP presents pre-localized times for everything, we need to get
    # the server's time offset, and compute the difference between that and
    # our timestamp, to appropriately apply time localization.
    my $srvParms;
    my $rc = $$obj{'afpconn'}->FPGetSrvrParms(\$srvParms);
    if ($rc != kFPNoErr) {
        $obj->disconnect();
        return EACCES;
    }
    $$obj{'timedelta'} = time() - $$srvParms{'ServerTime'};

    # Open the volume indicated at start time, and abort if the server bitches
    # at us.
    # open volume {{{2
    my $volInfo;
    $rc = $$obj{'afpconn'}->FPOpenVol(kFPVolAttributeBit |
            kFPVolSignatureBit, $urlparms{'volume'}, undef,
            \$volInfo);
    if ($rc == kFPAccessDenied) {
        # no volume password; does apple's AFP server even support volume
        # passwords anymore? I don't really know.
        print "Server expected volume password\n";
        $obj->disconnect();
        return EACCES;
    }
    elsif ($rc == kFPObjectNotFound || $rc == kFPParamErr) {
        # Server didn't know the volume we asked for.
        print 'Volume "', $urlparms{'volume'}, "\" does not exist on server\n";
        $obj->disconnect();
        return ENODEV;
    }
    elsif ($rc != kFPNoErr) {
        # Some other error occurred; if the docs are to be believed, this should
        # never happen unless we pass bad flags (coding error) or some
        # non-AFP-specific condition causes a failure (which is out of our
        # hands)...
        print 'FPOpenVol failed with error ', $rc, ' (',
                afp_strerror($rc), ")\n";
        $obj->disconnect();
        return ENODEV;
    }
    print Dumper($volInfo) if defined $::_DEBUG;

    if ($$volInfo{'Signature'} == 3) {
        print "Volume uses variable Directory IDs; not currently supported\n";
        $obj->disconnect();
        return EINVAL;
    }

    $$obj{'volID'} = $$volInfo{'ID'};
    # Copy out the attribute value, since there are some flags we should really
    # be checking in there (you know, for UTF8 support, extended attributes,
    # ACLs, things like that)...
    $$obj{'volAttrs'} = $$volInfo{'VolAttribute'};

    $$obj{'pathType'}   = kFPLongName; # AFP long names by default
    $$obj{'pathFlag'}   = kFPLongNameBit;
    $$obj{'pathkey'}    = 'LongName';

    if ($$obj{'volAttrs'} & kSupportsUTF8Names) {
        # If the remote volume does UTF8 names, then we'll go with that..
        $$obj{'pathType'}   = kFPUTF8Name;
        $$obj{'pathFlag'}   = kFPUTF8NameBit;
        $$obj{'pathkey'}    = 'UTF8Name';
    }

    $$obj{'DForkLenFlag'}   = kFPDataForkLenBit;
    $$obj{'RForkLenFlag'}   = kFPRsrcForkLenBit;
    $$obj{'DForkLenKey'}    = 'DataForkLen';
    $$obj{'RForkLenKey'}    = 'RsrcForkLen';
    $$obj{'UseExtOps'}      = 0;
    $$obj{'ReadFn'}         = \&Net::AFP::FPRead;
    $$obj{'WriteFn'}        = \&Net::AFP::FPWrite;
    $$obj{'EnumFn'}         = \&Net::AFP::FPEnumerate;
    # I *think* large file support entered the picture as of AFP 3.0...
    if (Net::AFP::Versions::CompareByVersionNum($$obj{'afpconn'}, 3, 0,
            kFPVerAtLeast)) {
        $$obj{'DForkLenFlag'}   = kFPExtDataForkLenBit;
        $$obj{'RForkLenFlag'}   = kFPExtRsrcForkLenBit;
        $$obj{'DForkLenKey'}    = 'ExtDataForkLen';
        $$obj{'RForkLenKey'}    = 'ExtRsrcForkLen';
        $$obj{'UseExtOps'}      = 1;
        $$obj{'ReadFn'}         = \&Net::AFP::FPReadExt;
        $$obj{'WriteFn'}        = \&Net::AFP::FPWriteExt;
    }
    if (Net::AFP::Versions::CompareByVersionNum($$obj{'afpconn'}, 3, 1,
            kFPVerAtLeast)) {
        $$obj{'EnumFn'}         = \&Net::AFP::FPEnumerateExt2;
    }

    # Not checking the return code here. If this fails, $$self{'DTRefNum'}
    # won't be defined, so we don't need to worry about possible later
    # unpredictable failures due to this.
    $$obj{'afpconn'}->FPOpenDT($$obj{'volID'}, \$$obj{'DTRefNum'});

    if ($$obj{'volAttrs'} & kSupportsACLs) {
        if ($has_Data__UUID) {
            my $uo = new Data::UUID;
            $$obj{'client_uuid'} = $uo->create();
        } else {
            print "Need Data::UUID class for full ACL functionality, ACL checking disabled\n";
        }
    }
    # }}}2

    # If a subpath is defined, find the node ID for the directory, and use that
    # as the root; if the node isn't found or is not a directory, then abort.
    # lookup node ID for subpath mount {{{2
    if (defined $urlparms{'subpath'}) {
        print 'Looking up directory \'', $urlparms{'subpath'},
                "' as pivot point for root node\n" if defined $::_DEBUG;
        my $realDirPath = translate_path($urlparms{'subpath'});
        my $dirBitmap = kFPNodeIDBit;

        my $resp;
        ($rc, $resp) = $$obj{'afpconn'}->FPGetFileDirParms(
                'VolumeID'          => $$obj{'volID'},
                'DirectoryID'       => $$obj{'topDirID'},
                'FileBitmap'        => $dirBitmap,
                'DirectoryBitmap'   => $dirBitmap,
                'PathType'          => $$obj{'pathType'},
                'Pathname'          => $realDirPath);

        if ($rc != kFPNoErr || !exists $$resp{'NodeID'}) {
            print STDERR "ERROR: Specified directory not found\n";
            $obj->disconnect();
            return ENODEV;
        }

        if ($$resp{'FileIsDir'} != 1) {
            print STDERR "ERROR: Attempted to pivot mount root to non-directory\n";
            $obj->disconnect();
            return ENOTDIR;
        }
        $$obj{'topDirID'} = $$resp{'NodeID'};
        print "Mount root node ID changed to ", $$obj{'topDirID'}, "\n"
                if defined $::_DEBUG;
    } # }}}2

    # purify URL # {{{2
    my $scrubbed_url = $urlparms{'protocol'} . ':/';
    if ($urlparms{'atalk_transport'}) {
        $scrubbed_url .= $urlparms{'atalk_transport'};
    }
    $scrubbed_url .= '/';
    if (defined $urlparms{'username'}) {
        $scrubbed_url .= urlencode($urlparms{'username'}) . '@';
    }
    if ($urlparms{'host'} =~ /:/) {
        $scrubbed_url .= '[' . $urlparms{'host'} . ']';
    }
    else {
        $scrubbed_url .= urlencode($urlparms{'host'});
    }
    if (defined $urlparms{'port'}) {
        $scrubbed_url .= ':' . $urlparms{'port'};
    }
    $scrubbed_url .= '/';
    if (defined $urlparms{'volume'}) {
        $scrubbed_url .= urlencode($urlparms{'volume'});
        if (defined $urlparms{'subpath'}) {
            $scrubbed_url .= urlencode($urlparms{'subpath'});
        }
    }
    $_[1] = $scrubbed_url;
    # }}}2

    return $obj;
} # }}}1

sub disconnect { # {{{1
    my ($self) = @_;

    if (defined $$self{'afpconn'}) {
        $$self{'afpconn'}->FPCloseDT($$self{'DTRefNum'})
                if defined $$self{'DTRefNum'};
        $$self{'afpconn'}->FPCloseVol($$self{'volID'})
                if defined $$self{'volID'};
        $$self{'afpconn'}->FPLogout();
        $$self{'afpconn'}->close();
    }
    return;
} # }}}1

sub getattr { # {{{1
    my ($self, $file) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my ($rc, $resp) = $self->lookup_afp_entry($fileName);
    return $rc if $rc != kFPNoErr;

    return -&ENOENT if $$resp{'NodeID'} == 0;

    # assemble stat record {{{2
    my @stat = (
        # device number (just make it 0, since it's not a real device)
        0,
        # inode number (node ID works fine)
        $$resp{'NodeID'},
        # permission mask
        exists($$resp{'UnixPerms'}) ? $$resp{'UnixPerms'} :
                ($$resp{'FileIsDir'} ? 040755 : 0100644),
        # link count; not really technically correct (should just be the
        # number of subdirs), but there's not a convenient way to get just
        # that via AFP, other than walking the directory. for what it's
        # worth, it looks (empirically) like this is what apple's client
        # does too, instead of walking the dir.
        $$resp{'FileIsDir'} ? $$resp{'OffspringCount'} + 2 : 1,
        # UID number
        exists($$resp{'UnixUID'}) ? $$resp{'UnixUID'} : 0,
        # GID number
        exists($$resp{'UnixGID'}) ? $$resp{'UnixGID'} : 0,
        # device special major/minor number
        0,
        # file size in bytes
        $$resp{'FileIsDir'} ? 4096 : $$resp{$$self{'DForkLenKey'}},
        # last accessed time
        $$resp{'ModDate'} + $$self{'timedelta'},
        # data modified time
        $$resp{'ModDate'} + $$self{'timedelta'},
        # inode changed time
        $$resp{'CreateDate'} + $$self{'timedelta'},
        # preferred block size
        512,
        # size in blocks
        $$resp{'FileIsDir'} ? 1 : int(($$resp{$$self{'DForkLenKey'}} - 1) / 512) + 1
    );
    # }}}2
    return(@stat);
} # }}}1

sub readlink { # {{{1
    my ($self, $file) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    # Classic MacOS' concept of an "alias", so far as I can tell, doesn't
    # really translate to the UNIX concept of a symlink; I might be able
    # to implement it later via file IDs, but until then, if UNIX permissions
    # aren't present, this won't work.
    return -&EINVAL unless $$self{'volAttrs'} & kSupportsUnixPrivs;

    $file = decode(ENCODING, $file);
    # Break the provided path down into a directory ID and filename.
    my $fileName = translate_path($file);

    # Get the UNIX privilege info for the file.
    my $fileBitmap = kFPUnixPrivsBit;
    my($rc, $resp) = $$self{'afpconn'}->FPGetFileDirParms(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$self{'topDirID'},
            'FileBitmap'    => $fileBitmap,
            'PathType'      => $$self{'pathType'},
            'Pathname'      => $fileName);
    return -&EACCES if $rc == kFPAccessDenied;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EBADF  if $rc != kFPNoErr;

    # The UNIX privilege info is pretty universal, so just use the standard
    # macros to see if the permissions show it to be a symlink.
    # process symlink {{{2
    if (S_ISLNK($$resp{'UnixPerms'})) {
        # Now we have to open the "data fork" of this pseudo-file, read the
        # "contents" (a single line containing the path of the symbolic link),
        # and return that.
        my %sresp;
        ($rc, %sresp) = $$self{'afpconn'}->FPOpenFork(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'AccessMode'    => 0x1,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EINVAL if $rc == kFPParamErr;
        return -&EMFILE if $rc == kFPTooManyFilesOpen;
        return -&EBADF  if $rc != kFPNoErr;

        my $linkPath;
        my $pos = 0;
        do {
            my $readText;
            ($rc, $readText) = &{$$self{'ReadFn'}}($$self{'afpconn'},
                    'OForkRefNum'   => $sresp{'OForkRefNum'},
                    'Offset'        => $pos,
                    'ReqCount'      => 1024);
            return -&EACCES if $rc == kFPAccessDenied;
            return -&EINVAL unless $rc == kFPNoErr or $rc == kFPEOFErr;
            $linkPath .= $readText;
        } until ($rc == kFPEOFErr);
        $$self{'afpconn'}->FPCloseFork($sresp{'OForkRefNum'});
        return encode(ENCODING, $linkPath);
    } # }}}2

    return -&EINVAL;
} # }}}1

sub getdir { # {{{1
    my ($self, $dirname) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $dirname = decode(ENCODING, $dirname);
    my $fileName = translate_path($dirname);
    my @filesList = ('.', '..');

    if (defined $$self{'client_uuid'}) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_LIST_DIRECTORY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    my $resp;
    # Set the result set size limit; if there are more entries in the
    # directory, extra requests will have to be sent. Larger set sizes
    # mean less time spent waiting around for responses.
    my $setsize = 500;
    my %arglist = ( 'VolumeID'          => $$self{'volID'},
                    'DirectoryID'       => $$self{'topDirID'},
                    'FileBitmap'        => $$self{'pathFlag'},
                    'DirectoryBitmap'   => $$self{'pathFlag'},
                    'ReqCount'          => $setsize,
                    'StartIndex'        => 1,
                    'MaxReplySize'      => 32767,
                    'PathType'          => $$self{'pathType'},
                    'Pathname'          => $fileName,
                    'Entries_ref'       => \$resp);
    my $rc = undef;
    # loop reading entries {{{2
    while (1) {
        $rc = &{$$self{'EnumFn'}}($$self{'afpconn'}, %arglist);

        last unless $rc == kFPNoErr;

        # Under some circumstances (no, this is not an error elsewhere in
        # my code, near as I can tell) on a second swipe, we'll get *one*
        # dirent back, which is a file we already got. that means that's
        # the end.
        if ($arglist{'StartIndex'} > 1 &&
                ($$resp[0]{$$self{'pathkey'}} eq $filesList[-1])) {
            shift(@$resp);
            $arglist{'StartIndex'}++;
        }
        # anyone actually trying to readdir() gets the entries in reverse
        # order, for some odd reason; bug in FUSE driver/libfuse/Fuse module?
        foreach my $elem (@$resp) {
            my $name = $$elem{$$self{'pathkey'}};
            $name =~ tr|/|:|;
            push(@filesList, encode(ENCODING, $name));
        }
        #push(@filesList, map {
        #                my $name = $$_{$$self{'pathkey'}};
        #                $name =~ tr/\//:/;
        #                encode(ENCODING, $name); } @$resp);

        # Set up for a subsequent call to get directory entries.
        $arglist{'StartIndex'} += scalar(@$resp);
        undef $resp;
    }
    # }}}2
    if ($rc == kFPObjectNotFound or $rc == kFPNoErr) {
        return(reverse(@filesList), 0);
    }
    return -&EACCES  if $rc == kFPAccessDenied;
    return -&ENOENT  if $rc == kFPDirNotFound;
    return -&ENOTDIR if $rc == kFPObjectTypeErr;
    return -&EINVAL  if $rc == kFPParamErr;
    return -&EACCES;
}
# }}}1

sub mknod { # {{{1
    my ($self, $file, $mode, $devnum) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    if (S_ISREG($mode)) {
        my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
        return $rc if $rc != kFPNoErr;
        if (defined $$self{'client_uuid'}) {
            $rc = $$self{'afpconn'}->FPAccess(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'UUID'          => $$self{'client_uuid'},
                    'ReqAccess'     => KAUTH_VNODE_ADD_FILE,
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => path_parent($fileName));
            return -&EACCES if $rc == kFPAccessDenied;
            return -&ENOENT if $rc == kFPObjectNotFound;
            return -&EBADF  if $rc != kFPNoErr;
        }

        $rc = $$self{'afpconn'}->FPCreateFile(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$resp{'NodeID'},
                 'PathType'     => $$self{'pathType'},
                 'Pathname'     => node_name($fileName));
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOSPC if $rc == kFPDiskFull;
        return -&EBUSY  if $rc == kFPFileBusy;
        return -&EEXIST if $rc == kFPObjectExists;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EINVAL if $rc == kFPParamErr;
        return -&EROFS  if $rc == kFPVolLocked;
        return -&EBADF  if $rc != kFPNoErr;
        return 0;
    }
    return -&EOPNOTSUPP;
} # }}}1

sub mkdir { # {{{1
    my ($self, $file, $mode) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
    return $rc if $rc != kFPNoErr;
    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_ADD_SUBDIRECTORY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => path_parent($fileName));
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    $rc = $$self{'afpconn'}->FPCreateDir(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$resp{'NodeID'},
            'PathType'      => $$self{'pathType'},
            'Pathname'      => node_name($fileName));
    return 0        if $rc == kFPNoErr;
    return -&EPERM  if $rc == kFPAccessDenied;
    return -&ENOSPC if $rc == kFPDiskFull;
    return -&EPERM  if $rc == kFPFlatVol;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EEXIST if $rc == kFPObjectExists;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF;
} # }}}1

sub unlink { # {{{1
    my ($self, $file) = @_;

    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
    return $rc if $rc != kFPNoErr;

    if (exists $$self{'ofcache'}{$fileName}) {
        $$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
        delete $$self{'ofcache'}{$fileName};
    }

    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_DELETE,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        #return -&ENOENT if $rc == kFPObjectNotFound;
        # HACK ALERT: Seems FPAccess() always follows links, so I can't
        # remove a dead symlink because the FPAccess() call always fails.
        # This works around that, but it's probably not the best solution.
        return -&EBADF  if $rc != kFPNoErr and $rc != kFPObjectNotFound;
    }

    # don't have to worry about checking to ensure we're 'rm'ing a file;
    # this works for both, verifying that "unlink" is being invoked on a
    # non-directory is done elsewhere. also, we're referencing this sub
    # as the implementation for rmdir as well, which should work just fine
    # since the same backend call does both.
    $rc = $$self{'afpconn'}->FPDelete($$self{'volID'}, $$resp{'NodeID'},
            $$self{'pathType'}, node_name($fileName));
    return 0            if $rc == kFPNoErr;
    return -&EACCES     if $rc == kFPAccessDenied;
    return -&EBUSY      if $rc == kFPFileBusy;
    return -&EBUSY      if $rc == kFPObjectLocked;
    return -&ENOENT     if $rc == kFPObjectNotFound;
    return -&EISDIR     if $rc == kFPObjectTypeErr;
    return -&EINVAL     if $rc == kFPParamErr;
    return -&EROFS      if $rc == kFPVolLocked;
    return -&ENOTEMPTY  if $rc == kFPDirNotEmpty;
    return -&EBADF;
} # }}}1

sub rmdir { return Net::AFP::Fuse::unlink(@_); }

# seems OS X 10.4 causes the newly created symlink to be locked, so once
# you create it, you can't remove it via AFP until you unmount the volume
# once. good work apple. :| doesn't happen on netatalk or OS X 10.5.
sub symlink { # {{{1
    my ($self, $target, $linkname) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    return -&EPERM unless $$self{'volAttrs'} & kSupportsUnixPrivs;

    $linkname = decode(ENCODING, $linkname);
    my $fileName = translate_path($linkname);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
    return $rc if $rc != kFPNoErr;
    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_ADD_FILE,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => path_parent($fileName));
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    # Seems that the Airport Disk AFP server doesn't like having
    # FPCreateFile called with the full path; have to get the node ID
    # of the containing directory and just pass the node name.

    # create the target file first
    # create target file {{{2
    $rc = $$self{'afpconn'}->FPCreateFile(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$resp{'NodeID'},
            'PathType'      => $$self{'pathType'},
            'Pathname'      => node_name($fileName));
    return -&EACCES if $rc == kFPAccessDenied;
    return -&ENOSPC if $rc == kFPDiskFull;
    return -&EBUSY  if $rc == kFPFileBusy;
    return -&EEXIST if $rc == kFPObjectExists;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF  if $rc != kFPNoErr;
    # }}}2

    # open the file, and write out the path given as the link target...
    # open and write link target {{{2
    my %sresp;
    ($rc, %sresp) = $$self{'afpconn'}->FPOpenFork(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$self{'topDirID'},
            'AccessMode'    => 0x3,
            'PathType'      => $$self{'pathType'},
            'Pathname'      => $fileName);
    return -&EACCES  if $rc == kFPAccessDenied;
    return -&ETXTBSY if $rc == kFPDenyConflict;
    return -&ENOENT  if $rc == kFPObjectNotFound;
    return -&EACCES  if $rc == kFPObjectLocked;
    return -&EISDIR  if $rc == kFPObjectTypeErr;
    return -&EINVAL  if $rc == kFPParamErr;
    return -&EMFILE  if $rc == kFPTooManyFilesOpen;
    return -&EROFS   if $rc == kFPVolLocked;
    return -&EBADF   if $rc != kFPNoErr;
    my $forkID = $sresp{'OForkRefNum'};

    my $lastWritten;
    ($rc, $lastWritten) = &{$$self{'WriteFn'}}($$self{'afpconn'},
            'OForkRefNum'   => $forkID,
            'Offset'        => 0,
            'ForkData'      => \$target);

    $$self{'afpconn'}->FPCloseFork($forkID);

    return -&EACCES  if $rc == kFPAccessDenied;
    return -&ENOSPC  if $rc == kFPDiskFull;
    return -&ETXTBSY if $rc == kFPLockErr;
    return -&EINVAL  if $rc == kFPParamErr;
    return -&EBADF   if $rc != kFPNoErr;
    # }}}2

    # set finder info {{{2
    my $bitmap = kFPFinderInfoBit | kFPModDateBit;

    # apparently this is the magic to transmute a file into a symlink...
    $rc = $$self{'afpconn'}->FPSetFileParms(
            'VolumeID'      =>$$self{'volID'},
            'DirectoryID'   => $$self{'topDirID'},
            'Bitmap'        => $bitmap,
            'PathType'      => $$self{'pathType'},
            'Pathname'      => $fileName,
            'FinderInfo'    => "slnkrhap\0\@" . "\0" x 22,
            'ModDate'       => time() - $$self{'timedelta'});
    
    return 0        if $rc == kFPNoErr;
    return -&EACCES if $rc == kFPAccessDenied;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EBADF;
    # }}}2

} # }}}1

sub rename { # {{{1
    my ($self, $oldName, $newName) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $oldName = decode(ENCODING, $oldName);
    $newName = decode(ENCODING, $newName);
    my @elems = split(/\//, $newName);
    my $newPath = join('/', @elems[0 .. ($#elems - 1)]);
    if ($newPath eq '') {
        $newPath = '/';
    }
    my $newRealName = $elems[-1];
    @elems = split(/\//, $oldName);
    my $oldRealName = $elems[-1];

    my $oldXlated = translate_path($oldName);
    my $newXlated = translate_path($newPath);
    
    my ($rc, $old_stat) = $self->lookup_afp_entry($oldXlated, 1);
    return $rc if $rc != kFPNoErr;
    my $new_stat;
    ($rc, $new_stat) = $self->lookup_afp_entry($newXlated);
    return $rc if $rc != kFPNoErr;

    # FIXME: is this the right access check to request? I'm really not
    # sure, but it seems to be the most sensible choice...
    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$old_stat{'ParentDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_DELETE,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $oldRealName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    my %arglist = ( 'VolumeID'              => $$self{'volID'},
                    'SourceDirectoryID'     => $$old_stat{'ParentDirID'},
                    'DestDirectoryID'       => $$new_stat{'NodeID'},
                    'SourcePathType'        => $$self{'pathType'},
                    'SourcePathname'        => $oldRealName,
                    'DestPathType'          => $$self{'pathType'},
                    'DestPathname'          => '',
                    'NewType'               => $$self{'pathType'},
                    'NewName'               => $newRealName );
    $rc = $$self{'afpconn'}->FPMoveAndRename(%arglist);

    if ($rc == kFPObjectExists) {
        $$self{'afpconn'}->FPDelete($$self{'volID'}, $$new_stat{'NodeID'},
                $$self{'pathType'}, $newRealName);
        $rc = $$self{'afpconn'}->FPMoveAndRename(%arglist);
    }
    if ($rc == kFPNoErr) {
        # Move the open filehandle for the renamed file to the new name,
        # if there is one.
        if (exists $$self{'ofcache'}{$oldXlated}) {
            $$self{'ofcache'}{$newXlated} = $$self{'ofcache'}{$oldXlated};
            delete $$self{'ofcache'}{$oldXlated};
        }
        return 0;
    }
    return -&EACCES if $rc == kFPAccessDenied;
    return -&EINVAL if $rc == kFPCantMove;
    return -&EBUSY  if $rc == kFPObjectLocked;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF;
} # }}}1

sub link { # {{{1
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;
    return -&EOPNOTSUPP;
} # }}}1

sub chmod { # {{{1
    my ($self, $file, $mode) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;
    
    my $fileName = translate_path(decode(ENCODING, $file));
    my ($rc, $resp) = $self->lookup_afp_entry($fileName, 1);
    return $rc if $rc != kFPNoErr;

    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_WRITE_ATTRIBUTES,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    $rc = $$self{'afpconn'}->FPSetFileDirParms(
            'VolumeID'          => $$self{'volID'},
            'DirectoryID'       => $$self{'topDirID'},
            'Bitmap'            => kFPUnixPrivsBit,
            'PathType'          => $$self{'pathType'},
            'Pathname'          => $fileName,
            'UnixPerms'         => $mode | S_IFMT($$resp{'UnixPerms'}),
            'UnixUID'           => $$resp{'UnixUID'},
            'UnixGID'           => $$resp{'UnixGID'},
            'UnixAccessRights'  => $$resp{'UnixAccessRights'});
    return -&EPERM  if $rc == kFPAccessDenied;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF  if $rc != kFPNoErr;

    return 0;
} # }}}1

sub chown { # {{{1
    my ($self, $file, $uid, $gid) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    my $fileName = translate_path(decode(ENCODING, $file));
    my ($rc, $resp) = $self->lookup_afp_entry($fileName, 1);
    return $rc if $rc != kFPNoErr;

    if (defined $$self{'client_uuid'}) {
        $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_CHANGE_OWNER,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    $rc = $$self{'afpconn'}->FPSetFileDirParms(
            'VolumeID'          => $$self{'volID'},
            'DirectoryID'       => $$self{'topDirID'},
            'Bitmap'            => kFPUnixPrivsBit,
            'PathType'          => $$self{'pathType'},
            'Pathname'          => $fileName,
            'UnixPerms'         => $$resp{'UnixPerms'},
            'UnixUID'           => $uid,
            'UnixGID'           => $gid,
            'UnixAccessRights'  => $$resp{'UnixAccessRights'});
    return -&EPERM  if $rc == kFPAccessDenied;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF  if $rc != kFPNoErr;

    return 0;
} # }}}1

sub truncate { # {{{1
    my ($self, $file, $length) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    my $ofork;
    my $close_fork = 0;

    if (defined $$self{'client_uuid'}) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_WRITE_DATA,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    my $rc;
    if (exists $$self{'ofcache'}{$fileName}) {
        $ofork = $$self{'ofcache'}{$fileName}{'refnum'};
    } else {
        my %resp;
        ($rc, %resp) = $$self{'afpconn'}->FPOpenFork(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'AccessMode'    => 0x3,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EPERM  if $rc == kFPAccessDenied;
        return -&EPERM  if $rc == kFPDenyConflict;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EPERM  if $rc == kFPObjectLocked;
        return -&EISDIR if $rc == kFPObjectTypeErr;
        return -&EINVAL if $rc == kFPParamErr;
        return -&EMFILE if $rc == kFPTooManyFilesOpen;
        return -&EROFS  if $rc == kFPVolLocked;
        return -&EBADF  if $rc != kFPNoErr;

        $ofork = $resp{'OForkRefNum'};
        $close_fork = 1;
    }

    $rc = $$self{'afpconn'}->FPSetForkParms($ofork, $$self{'DForkLenFlag'},
            $length);

    $$self{'afpconn'}->FPCloseFork($ofork) if $close_fork == 1;

    return 0        if $rc == kFPNoErr;
    return -&EPERM  if $rc == kFPAccessDenied;
    return -&ENOSPC if $rc == kFPDiskFull;
    return -&EPERM  if $rc == kFPLockErr;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF;
} # }}}1

sub utime { # {{{1
    my ($self, $file, $actime, $modtime) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my $rc = $$self{'afpconn'}->FPSetFileDirParms(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$self{'topDirID'},
            'Bitmap'        => kFPCreateDateBit | kFPModDateBit,
            'PathType'      => $$self{'pathType'},
            'Pathname'      => $fileName,
            'CreateDate'    => $actime - $$self{'timedelta'},
            'ModDate'       => $modtime - $$self{'timedelta'});
    return 0        if $rc == kFPNoErr;
    return -&EPERM  if $rc == kFPAccessDenied;
    return -&ENOENT if $rc == kFPObjectNotFound;
    return -&EINVAL if $rc == kFPParamErr;
    return -&EROFS  if $rc == kFPVolLocked;
    return -&EBADF;
} # }}}1

sub open { # {{{1
    my ($self, $file, $mode) = @_;
    print 'called ', (caller(0))[3], "('", $file, "', ", $mode, ")\n"
            if defined $::_DEBUG;

    my $refcount = 0;
    my $file_u = $file;
    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my $accessBitmap = 0x1;
    if (($mode & O_ACCMODE) == O_RDWR) {
        $accessBitmap = 0x3;
    } elsif (($mode & O_ACCMODE) == O_WRONLY) {
        # HACK: Thanks Apple. Way to, I don't know, know how to IMPLEMENT
        # YOUR OWN PROTOCOL. Seems if you open the file write-only, and
        # then, oh, try to WRITE TO IT, the writes then fail. Wow. That
        # makes so much sense!
        $accessBitmap = 0x3;
    } elsif (($mode & O_ACCMODE) == O_RDONLY) {
        $accessBitmap = 0x1;
    }

    # Speaking of being lied to, fuse claims release() doesn't get called
    # until the last reference goes away. Um... not so much really. It
    # happily closes and reopens filehandles mid-stream. This really
    # breaks the model. Fortunately a little refcounting fixes it
    # right up...
    if (exists $$self{'ofcache'}{$fileName}) {
        my $cachedBitmap = $$self{'ofcache'}{$fileName}{'mode'};
        if (($cachedBitmap & $accessBitmap) == $cachedBitmap) {
            $$self{'ofcache'}{$fileName}{'refcount'}++;
            return 0;
        }
        $self->flush($file_u);
        $refcount = $$self{'ofcache'}{$fileName}{'refcount'};
        my $rc = $$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
        delete $$self{'ofcache'}{$fileName};
        $accessBitmap = 0x3;
    }

    my($rc, %resp) = $$self{'afpconn'}->FPOpenFork(
            'VolumeID'      => $$self{'volID'},
            'DirectoryID'   => $$self{'topDirID'},
            'AccessMode'    => $accessBitmap,
            'PathType'      => $$self{'pathType'},
            'Pathname'      => $fileName);
    if ($rc == kFPNoErr) {
        $$self{'ofcache'}{$fileName} = {
                'ostamp'            => time(),
                'astamp'            => time(),
                'mode'              => $accessBitmap,
                'refnum'            => $resp{'OForkRefNum'},
                'coalesce_offset'   => undef,
                'coalesce_len'      => undef,
                'coalesce_buf'      => "\0" x COALESCE_MAX,
                'refcount'          => $refcount + 1 };
        return(0);
    }
    return -&EACCES  if $rc == kFPAccessDenied;
    return -&ETXTBSY if $rc == kFPDenyConflict;
    return -&ENOENT  if $rc == kFPObjectNotFound;
    return -&EACCES  if $rc == kFPObjectLocked;
    return -&EISDIR  if $rc == kFPObjectTypeErr;
    return -&EINVAL  if $rc == kFPParamErr;
    return -&EMFILE  if $rc == kFPTooManyFilesOpen;
    return -&EROFS   if $rc == kFPVolLocked;
    return -&EBADF;
} # }}}1

sub read { # {{{1
    my ($self, $file, $len, $off) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $self->fsync($file);

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    return -&EBADF unless exists $$self{'ofcache'}{$fileName};

    if (defined $$self{'client_uuid'}) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_READ_DATA,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    my $forkID = $$self{'ofcache'}{$fileName}{'refnum'};
    $$self{'ofcache'}{$fileName}{'astamp'} = time();
    my($rc, $resp) = &{$$self{'ReadFn'}}($$self{'afpconn'},
            'OForkRefNum'   => $forkID,
            'Offset'        => $off,
            'ReqCount'      => $len);
    return $resp     if $rc == kFPNoErr
            or $rc == kFPEOFErr;
    #return -&ESPIPE  if $rc == kFPEOFErr;
    return -&EBADF   if $rc == kFPAccessDenied;
    return -&ETXTBSY if $rc == kFPLockErr;
    return -&EINVAL  if $rc == kFPParamErr;
    return -&EBADF;
} # }}}1

sub write { # {{{1
    #my ($file, $data, $offset) = @_;
    my ($self, $file, $offset) = @_[0,1,3];
    my $data_r = \$_[2];
    print 'called ', (caller(0))[3], "('", $file, "', [data], ", $offset, ")\n"
            if defined $::_DEBUG;

    my $file_u = $file;
    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    return -&EBADF unless exists $$self{'ofcache'}{$fileName};

    my $of_ent = $$self{'ofcache'}{$fileName};
    my $forkID = $$of_ent{'refnum'};
    $$of_ent{'astamp'} = time();

    # This code implements write coalescing. FUSE 2.8 is supposed to be
    # implementing it at the libfuse level, but for now, doing lots of
    # small writes sucks for performance. This allows lots of small writes
    # to be bundled into fewer, large writes, which means less time spent
    # waiting for remote calls to be processed and less protocol overhead
    # to do it. Haven't yet benched it, but sequential write performance
    # via wget is notably better - I can saturate my Internet connection
    # with a download while writing to an AFP volume now.

    # coalesce writes {{{2
    if (defined $$of_ent{'coalesce_offset'} &&
            $$of_ent{'coalesce_len'} >= COALESCE_MAX) {
        my $rv = $self->flush($file_u);
        if ($rv != 0) {
            return $rv;
        }
    }

    if (defined $$self{'client_uuid'}) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_WRITE_DATA,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
    }

    my $dlen = length($$data_r);
    if (defined $$of_ent{'coalesce_offset'}) {
        if ($offset == ($$of_ent{'coalesce_offset'} +
                $$of_ent{'coalesce_len'})) {
            substr($$of_ent{'coalesce_buf'}, $$of_ent{'coalesce_len'},
                    $dlen, $$data_r);
            $$of_ent{'coalesce_len'} += $dlen;
            return $dlen;
        } else {
            my $rv = $self->flush($file_u);
            if ($rv != 0) {
                return $rv;
            }
        }
    } else {
        substr($$of_ent{'coalesce_buf'}, 0, $dlen, $$data_r);
        $$of_ent{'coalesce_len'} = $dlen;
        $$of_ent{'coalesce_offset'} = $offset;
        return length($$data_r);
    }
    # }}}2
    my($rc, $lastWritten) = &{$$self{'WriteFn'}}($$self{'afpconn'},
            'OForkRefNum'   => $forkID,
            'Offset'        => $offset,
            'ReqCount'      => $dlen,
            'ForkData'      => $data_r);
    
    return($lastWritten - $offset) if $rc == kFPNoErr;
    return -&EACCES      if $rc == kFPAccessDenied;
    return -&ENOSPC      if $rc == kFPDiskFull;
    return -&ETXTBSY     if $rc == kFPLockErr;
    return -&EINVAL      if $rc == kFPParamErr;
    return -&EBADF;
} # }}}1

sub statfs { # {{{1
    my ($self) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;
    my $VolBitmap;
    my $bf_key;
    my $bt_key;
    my $blocksize = 512;
    if ($$self{'UseExtOps'}) {
        $VolBitmap |= kFPVolExtBytesFreeBit | kFPVolExtBytesTotalBit |
                      kFPVolBlockSizeBit;
        $bf_key = 'ExtBytesFree';
        $bt_key = 'ExtBytesTotal';
    } else {
        $VolBitmap |= kFPVolBytesFreeBit | kFPVolBytesTotalBit;
        $bf_key = 'BytesFree';
        $bt_key = 'BytesTotal';
    }
    my $resp;
    my $rc = $$self{'afpconn'}->FPGetVolParms($$self{'volID'}, $VolBitmap,
            \$resp);
    if (exists $$resp{'BlockSize'}) {
        $blocksize = $$resp{'BlockSize'};
    }
    my @statinfo = (
            # namelen (?)
            255,
            # file count; not really (we're lying here), but afp doesn't
            # keep an "existing files" count
            int($$resp{$bt_key} / $blocksize),
            # files_free count; lying again, but afp doesn't have a concept
            # of "free inodes" either, it's not aware of such stuff
            int($$resp{$bf_key} / $blocksize),
            # total blocks
            int($$resp{$bt_key} / $blocksize),
            # free blocks
            int($$resp{$bf_key} / $blocksize),
            # block size
            $blocksize);
    return(@statinfo);
} # }}}1

sub flush { # {{{1
    my ($self, $file) = @_;
    print 'called ', (caller(0))[3], "('", $file, "')\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    if (exists $$self{'ofcache'}{$fileName}) {
        # This is the second (and critical) part of write coalescing -
        # flushing the writes out to the remote volume. I'm probably
        # implementing this in a rather naive fashion, but it works so
        # far...
        if (defined $$self{'ofcache'}{$fileName}{'coalesce_offset'}) {
            my($forkID, $offset, $len) =
                    @{$$self{'ofcache'}{$fileName}}{'refnum', 'coalesce_offset',
                                              'coalesce_len'};
            my $data_ref = \$$self{'ofcache'}{$fileName}{'coalesce_buf'};
#           if ($$self{'ofcache'}{$fileName}{'coalesce_len'} < COALESCE_MAX) {
#               my $data = substr($$data_ref, 0, $$self{'ofcache'}{$fileName}{'coalesce_len'});
#               $data_ref = \$data;
#           }

            # Try to zero-copy whenever possible...
            my ($rc, $lastwr)= &{$$self{'WriteFn'}}($$self{'afpconn'},
                    'OForkRefNum'   => $forkID,
                    'Offset'        => $offset,
                    'ReqCount'      => $len,
                    'ForkData'      => $data_ref);
            # Continue writing if needed.
            while ($lastwr < ($offset + $len) && $rc == kFPNoErr) {
                my $dchunk = substr($$data_ref, $lastwr - $offset,
                        $offset + $len - $lastwr);
                ($rc, $lastwr) = &{$$self{'WriteFn'}}($$self{'afpconn'},
                        'OForkRefNum'   => $forkID,
                        'Offset'        => $lastwr,
                        'ForkData'      => \$dchunk);
            }
            undef $$self{'ofcache'}{$fileName}{'coalesce_offset'};
        }
    }

    return(0);
} # }}}1

sub release { # {{{1
    my ($self, $file, $mode) = @_;
    print 'called ', (caller(0))[3], "('", $file, "', ", $mode, ")\n"
            if defined $::_DEBUG;

    my $file_u = $file;
    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    if (exists $$self{'ofcache'}{$fileName}) {
        # If the reference count is not 0, just play along.
        return(0) if --$$self{'ofcache'}{$fileName}{'refcount'};
        $self->flush($file_u);
        $$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
        delete $$self{'ofcache'}{$fileName};
        return 0;
    }
    return -&EBADF;
} # }}}1

sub fsync { # {{{1
    my ($self, $file, $flags) = @_;
    print 'called ', (caller(0))[3], "('", $file, "')\n"
            if defined $::_DEBUG;

    return $self->flush($file);
} # }}}1

sub setxattr { # {{{1
    my ($self, $file, $attr, $value, $flags) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    $attr = decode(ENCODING, $attr);

    # handle ACL xattr {{{2
    if ($attr eq ACL_XATTR && defined($$self{'client_uuid'})) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_WRITE_SECURITY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;

        # if either of the flags is present, apply extra checking for the
        # presence of an ACL.
        if ($flags) {
            my %resp;
            ($rc, %resp) = $$self{'afpconn'}->FPGetACL(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            if ($flags & XATTR_CREATE) {
                return -&EEXIST if $resp{'Bitmap'} & kFileSec_ACL;
            }
            elsif ($flags & XATTR_REPLACE) {
                return -&ENODATA unless $resp{'Bitmap'} & kFileSec_ACL;
            }
        }
    
        my $acl;
        my $rv = $self->acl_from_xattr($value, \$acl);
        if ($rv != 0) {
            return $rv;
        }
        # send the ACL on to the AFP server.
        $rc = $$self{'afpconn'}->FPSetACL(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => kFileSec_ACL,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName,
                %$acl);
        return -&EACCES  if $rc == kFPAccessDenied;
        return -&ENOENT  if $rc == kFPObjectNotFound;
        return -&EBADF   if $rc != kFPNoErr;
        return 0;
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
        # If either of the flags is present, apply extra checking for the
        # presence of a finder comment.
        if ($flags) {
            my($rc, $comment) = $$self{'afpconn'}->FPGetComment(
                    'DTRefNum'      => $$self{'DTRefNum'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            if ($flags & XATTR_CREATE) {
                return -&EEXIST
                        if $rc == kFPItemNotFound;
            }
            elsif ($flags & XATTR_REPLACE) {
                return -&ENODATA
                        unless $rc == kFPItemNotFound;
            }
        }
        my $rc = $$self{'afpconn'}->FPAddComment(
                'DTRefNum'      => $$self{'DTRefNum'},
                'DirectoryID'   => $$self{'topDirID'},
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName,
                'Comment'       => $value);
        return -&EACCES     if $rc == kFPAccessDenied;
        return -&ENOENT     if $rc == kFPObjectNotFound;
        return -&EOPNOTSUPP if $rc == kFPCallNotSupported;
        return -&EBADF      if $rc != kFPNoErr;
        return 0;
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ /^user\./) {
        $attr =~ s/^user\.//;

        return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;

        if (defined $$self{'client_uuid'}) {
            my $rc = $$self{'afpconn'}->FPAccess(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'UUID'          => $$self{'client_uuid'},
                    'ReqAccess'     => KAUTH_VNODE_WRITE_EXTATTRIBUTES,
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            return -&EACCES if $rc == kFPAccessDenied;
            return -&ENOENT if $rc == kFPObjectNotFound;
            return -&EBADF  if $rc != kFPNoErr;
        }

        # Set flags to pass to the server for special handling of the
        # extended attribute.
        my $xaflags = kXAttrNoFollow;
        if ($flags & XATTR_CREATE) {
            $xaflags |= kXAttrCreate;
        }
        if ($flags & XATTR_REPLACE) {
            $xaflags |= kXAttrReplace;
        }
        # Send the set request to the server.
        my $rc = $$self{'afpconn'}->FPSetExtAttr(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => $xaflags,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName,
                'Name'          => $attr,
                'AttributeData' => $value);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        # hopefully this is correct...
        if ($rc == kFPMiscErr) {
            return -&EEXIST  if $flags & XATTR_CREATE;
            return -&ENODATA if $flags & XATTR_REPLACE;
        }
        return -&EBADF  if $rc != kFPNoErr;
        return 0;
    } # }}}2
    return -&EOPNOTSUPP;
} # }}}1

sub getxattr { # {{{1
    my ($self, $file, $attr) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    $attr = decode(ENCODING, $attr);
    # handle ACL xattr {{{2
    if ($attr eq ACL_XATTR &&
            defined($$self{'client_uuid'})) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_READ_SECURITY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&ENODATA if $rc == kFPAccessDenied;
        return -&ENODATA if $rc == kFPObjectNotFound;
        return -&EBADF   if $rc != kFPNoErr;

        # get the ACL from the server.
        my %resp;
        ($rc, %resp) = $$self{'afpconn'}->FPGetACL(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&ENODATA if $rc == kFPAccessDenied;
        return -&ENODATA if $rc == kFPObjectNotFound;
        return -&EBADF   if $rc != kFPNoErr;
        # Check to see if the server actually sent us an ACL in its
        # response; if the file has no ACL, it'll just not return one.
        if ($resp{'Bitmap'} & kFileSec_ACL) {
            return $self->acl_to_xattr(\%resp);
        }
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
        # If the desktop DB was opened, then try getting the finder comment
        # for the file. If one is present, return it.
        my($rc, $comment) = $$self{'afpconn'}->FPGetComment(
                'DTRefNum'      => $$self{'DTRefNum'},
                'DirectoryID'   => $$self{'topDirID'},
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        if ($rc == kFPNoErr && defined($comment)) {
            return $comment;
        }
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ /^user\./) {
        $attr =~ s/^user\.//;

        return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;

        if (defined $$self{'client_uuid'}) {
            my $rc = $$self{'afpconn'}->FPAccess(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'UUID'          => $$self{'client_uuid'},
                    'ReqAccess'     => KAUTH_VNODE_READ_EXTATTRIBUTES,
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            return -&ENODATA if $rc == kFPAccessDenied;
            return -&ENODATA if $rc == kFPObjectNotFound;
            return -&EBADF   if $rc != kFPNoErr;
        }

        # FIXME: Should probably call this twice, once to get attr data size,
        # then once to get actual attr data, rather than hoping our assumed
        # size is enough...
        my($rc, %resp) = $$self{'afpconn'}->FPGetExtAttr(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => kXAttrNoFollow,
                'MaxReplySize'  => 131072,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName,
                'Name'          => $attr);
        return -&ENODATA if $rc == kFPAccessDenied;
        return -&ENODATA if $rc == kFPObjectNotFound;
        # hopefully this is correct...
        return -&ENODATA if $rc == kFPMiscErr;
        return -&EBADF   if $rc != kFPNoErr;
        if (defined $resp{'AttributeData'} &&
                $resp{'AttributeData'} ne '') {
            return $resp{'AttributeData'};
        }
    } # }}}2
    return -&EOPNOTSUPP;
} # }}}1

sub listxattr { # {{{1
    my ($self, $file) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;
    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);

    my @attrs;

    # general xattr handling {{{2
    if ($$self{'volAttrs'} & kSupportsExtAttrs) {
        if (defined $$self{'client_uuid'}) {
            my $rc = $$self{'afpconn'}->FPAccess(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'UUID'          => $$self{'client_uuid'},
                    'ReqAccess'     => KAUTH_VNODE_READ_EXTATTRIBUTES,
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            return -&EACCES if $rc == kFPAccessDenied;
            return -&ENOENT if $rc == kFPObjectNotFound;
            return -&EBADF  if $rc != kFPNoErr;
        }

        # Ask the server what extended attributes it knows for the file.
        # FIXME: Should probably request this twice, once with no
        # MaxReplySize to get the length, then once with the appropriate
        # size, instead of guessing and hoping.
        my ($rc, %resp) = $$self{'afpconn'}->FPListExtAttrs(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => kXAttrNoFollow,
                'MaxReplySize'  => 131072,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;
        @attrs = map { 'user.' . $_ } @{$resp{'AttributeNames'}};
    } # }}}2

    # Try getting the ACL for the indicated file; if there's an ACL
    # present, then include the special name in the list of extended
    # attributes.
    # handle ACL xattr {{{2
    if (defined $$self{'client_uuid'}) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_READ_SECURITY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;

        my %resp;
        ($rc, %resp) = $$self{'afpconn'}->FPGetACL(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        if ($rc == kFPNoErr && ($resp{'Bitmap'} & kFileSec_ACL)) {
            push(@attrs, ACL_XATTR);
        }
    } # }}}2
    # If the desktop DB was opened (should have been...), check for a
    # finder comment on the file.
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    if (defined $$self{'DTRefNum'}) {
        my($rc, $comment) = $$self{'afpconn'}->FPGetComment(
                'DTRefNum'      => $$self{'DTRefNum'},
                'DirectoryID'   => $$self{'topDirID'},
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        if ($rc == kFPNoErr && defined($comment)) {
            push(@attrs, COMMENT_XATTR);
        }
    } # }}}2
    return(@attrs, 0);
} # }}}1

sub removexattr { # {{{1
    my ($self, $file, $attr) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    $file = decode(ENCODING, $file);
    my $fileName = translate_path($file);
    $attr = decode(ENCODING, $attr);
    # handle ACL xattr {{{2
    if ($attr eq ACL_XATTR &&
            defined($$self{'client_uuid'})) {
        my $rc = $$self{'afpconn'}->FPAccess(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'UUID'          => $$self{'client_uuid'},
                'ReqAccess'     => KAUTH_VNODE_WRITE_SECURITY,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);
        return -&EACCES if $rc == kFPAccessDenied;
        return -&ENOENT if $rc == kFPObjectNotFound;
        return -&EBADF  if $rc != kFPNoErr;

        # Remove the ACL from the indicated file.
        $rc = $$self{'afpconn'}->FPSetACL(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => kFileSec_REMOVEACL,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName);

        return -&EACCES  if $rc == kFPAccessDenied;
        return -&ENOENT  if $rc == kFPObjectNotFound;
        return -&EBADF   if $rc != kFPNoErr;
        return 0;
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
        # Remove the finder comment, if one is present.
        my $rc = $$self{'afpconn'}->FPRemoveComment($$self{'DTRefNum'},
                $$self{'topDirID'}, $$self{'pathType'}, $fileName);
        return -&EACCES  if $rc == kFPAccessDenied;
        return -&ENODATA if $rc == kFPItemNotFound;
        return -&ENOENT  if $rc == kFPObjectNotFound;
        return -&EBADF   if $rc != kFPNoErr;
        return 0;
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ /^user\./) {
        $attr =~ s/^user\.//;

        return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;
        if (defined $$self{'client_uuid'}) {
            my $rc = $$self{'afpconn'}->FPAccess(
                    'VolumeID'      => $$self{'volID'},
                    'DirectoryID'   => $$self{'topDirID'},
                    'UUID'          => $$self{'client_uuid'},
                    'ReqAccess'     => KAUTH_VNODE_WRITE_EXTATTRIBUTES,
                    'PathType'      => $$self{'pathType'},
                    'Pathname'      => $fileName);
            return -&EACCES if $rc == kFPAccessDenied;
            return -&ENOENT if $rc == kFPObjectNotFound;
            return -&EBADF  if $rc != kFPNoErr;
        }

        # Remove the requested extended attribute from the indicated file.
        my $rc = $$self{'afpconn'}->FPRemoveExtAttr(
                'VolumeID'      => $$self{'volID'},
                'DirectoryID'   => $$self{'topDirID'},
                'Bitmap'        => kXAttrNoFollow,
                'PathType'      => $$self{'pathType'},
                'Pathname'      => $fileName,
                'Name'          => $attr);
        return -&EACCES  if $rc == kFPAccessDenied;
        return -&ENOENT  if $rc == kFPObjectNotFound;
        # hopefully this is correct...
        return -&ENODATA if $rc == kFPParamErr;
        return -&EBADF   if $rc != kFPNoErr;
        return 0;
    } # }}}2
    return -&ENODATA;
} # }}}1


# misc. helper functions below:

sub lookup_afp_entry { # {{{1
    my ($self, $fileName, $deleteEntry) = @_;

    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;

    # Disabling this for now, as it causes errors with dangling, but otherwise
    # well-formed, symlinks.
#    if (defined $$self{'client_uuid'}) {
#        my $rc = $$self{'afpconn'}->FPAccess(
#                'VolumeID'      => $$self{'volID'},
#                'DirectoryID'   => $$self{'topDirID'},
#                'UUID'          => $$self{'client_uuid'},
#                'ReqAccess'     => KAUTH_VNODE_READ_ATTRIBUTES,
#                'PathType'      => $$self{'pathType'},
#                'Pathname'      => $fileName);
#        return -&EACCES if $rc == kFPAccessDenied;
#        return -&ENOENT if $rc == kFPObjectNotFound;
#        return -&EBADF  if $rc != kFPNoErr;
#    }

    my $fileBitmap = kFPCreateDateBit | kFPModDateBit | kFPNodeIDBit |
                     kFPParentDirIDBit | $$self{'DForkLenFlag'};
    my $dirBitmap = kFPCreateDateBit | kFPModDateBit | kFPNodeIDBit |
                    kFPOffspringCountBit | kFPParentDirIDBit;
    if ($$self{'volAttrs'} & kSupportsUnixPrivs) {
        $fileBitmap |= kFPUnixPrivsBit;
        $dirBitmap |= kFPUnixPrivsBit;
    }

    my($rc, $resp) = $$self{'afpconn'}->FPGetFileDirParms(
            'VolumeID'          => $$self{'volID'},
            'DirectoryID'       => $$self{'topDirID'},
            'FileBitmap'        => $fileBitmap,
            'DirectoryBitmap'   => $dirBitmap,
            'PathType'          => $$self{'pathType'},
            'Pathname'          => $fileName);

    return($rc, $resp)  if $rc == kFPNoErr;
    return -&EACCES     if $rc == kFPAccessDenied;
    return -&ENOENT     if $rc == kFPObjectNotFound;
    return -&EINVAL     if $rc == kFPParamErr;
    return -&EBADF;
} # }}}1

sub translate_path { # {{{1
    my ($path) = @_;
    print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
            if defined $::_DEBUG;
    
    my @pathparts = split(/\//, $path);
    my @afp_path = ();
    foreach my $elem (@pathparts) {
        next if $elem eq '.';
        next if $elem eq '';
        if ($elem eq '..') {
            next if scalar(@afp_path) <= 0;
            pop(@afp_path);
            next;
        }
        $elem =~ tr/:/\//;
        push(@afp_path, $elem);
    }
    return join("\0", @afp_path);
} # }}}1

sub node_name { # {{{1
    my ($xlatedPath) = @_;

    my @path_parts = split(/\0/, $xlatedPath);
    return pop(@path_parts);
} # }}}1

sub path_parent { # {{{1
    my ($xlatedPath) = @_;

    my @path_parts = split(/\0/, $xlatedPath);
    pop(@path_parts);
    return join("\0", @path_parts);
} # }}}1

# Helper function to convert a byte-string form ACL from the ACL update client
# into the structured form to be sent to the server.
sub acl_from_xattr { # {{{1
    my ($self, $raw_xattr, $acl_data) = @_;

    # unpack the ACL from the client, so we can structure it to be handed
    # up to the AFP server
    my($acl_flags, @acl_parts) = unpack('NS/(LS/aLL)', $raw_xattr);
    my @entries;
    while (scalar(@acl_parts) > 0) {
        my $entry = {};
        my $bitmap = shift(@acl_parts);
        my $utf8name = decode_utf8(shift(@acl_parts));
        my($uuid, $rc);
        # do the appropriate type of name lookup based on the attributes
        # given in the bitmap field.
        if ($bitmap == kFileSec_UUID) {
            $rc = $$self{'afpconn'}->FPMapName(kUTF8NameToUserUUID, $utf8name,
                    \$uuid);
        } elsif ($bitmap == kFileSec_GRPUUID) {
            $rc = $$self{'afpconn'}->FPMapName(kUTF8NameToGroupUUID, $utf8name,
                    \$uuid);
        } else {
            $rc = $$self{'afpconn'}->FPMapName(kUTF8NameToUserUUID, $utf8name,
                    \$uuid);
            if ($rc == kFPItemNotFound) {
                $rc = $$self{'afpconn'}->FPMapName(kUTF8NameToGroupUUID,
                        $utf8name, \$uuid);
            }
        }
        # if we can't map a name to a UUID, then just tell the client
        # that we can't proceed.
        return -&EINVAL if $rc != kFPNoErr;

        $$entry{'ace_applicable'} = $uuid;
        $$entry{'ace_flags'} = shift(@acl_parts);
        $$entry{'ace_rights'} = shift(@acl_parts);
        push(@entries, $entry);
    }
    $$acl_data = {
                'acl_ace'   => [ @entries ],
                'acl_flags' => $acl_flags,
              };
    return 0;
} # }}}1

# Helper function to convert an AFP ACL into a format that is consumable
# by afp_acl.pl (the tool for manipulating ACLs on an AFP share).
sub acl_to_xattr { # {{{1
    my ($self, $acldata) = @_;

    my @acl_parts;
    foreach my $entry (@{$$acldata{'acl_ace'}}) {
        my $name;
        # map the UUID (this actually works for both user and group
        # UUIDs, the FPMapID docs are useless) to a corresponding
        # user or group name.
        my $rc = $$self{'afpconn'}->FPMapID(kUserUUIDToUTF8Name,
                $$entry{'ace_applicable'}, \$name);
        return -&EBADF if $rc != kFPNoErr;
        push(@acl_parts, pack('LS/aLL', $$name{'Bitmap'},
                encode_utf8($$name{'UTF8Name'}),
                @$entry{'ace_flags', 'ace_rights'}));
    }
    # Pack the ACL into a single byte sequence, and push it to
    # the client.
    return pack('LS/(a*)', $$acldata{'acl_flags'}, @acl_parts);
} # }}}1

sub urlencode { # {{{1
    my ($string) = @_;
    if (defined $string) {
        $string =~ s/([^\w\/_\-. ])/sprintf('%%%02x',ord($1))/gei;
        $string =~ tr/ /+/;
    }
    return $string;
} # }}}1

=back

=head1 DEPENDENCIES

This package derives from, and thus depends on, the Fuse::Class package.
By proxy, it also depends on the Fuse package, specifically version
0.09_5 or later, as it includes certain necessary fixes. The Net::AFP::TCP
and Net::AFP::Atalk packages are included in this code release.

=head1 BUGS AND LIMITATIONS

None currently known.

=head1 INCOMPATIBILITIES

When an AFP volume is mounted, if a user attempts to rsync a directory
hierarchy onto the AFP volume and there is a '.DS_Store' file in one of
them, rsync will get stuck in an infinite loop trying to open a temporary
file like '..DS_Store.XXXXXX' with O_CREAT, receiving EEXIST every time.
The AFP server really doesn't want anything named '.DS_Store' or anything
similar on the volume, as this is a "magic" file. There needs to be some
sort of workaround for this; I'm going to have to figure out how to do that.

=head1 AUTHOR

Derrik Pates <demon@devrandom.net

=head1 SEE ALSO

C<Fuse::Class>, C<Fuse>, C<Net::AFP>

=cut

1;
# vim: ts=4 fdm=marker sw=4 et
