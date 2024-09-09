package Fuse::AFP;

# Declare ourselves as a derivate of Fuse::Class.
use base qw(Fuse::Class);

# imports {{{1
use strict;
use warnings;
use diagnostics;
use feature qw(refaliasing);

# Tell Perl we need to be run in at least v5.10.
use 5.010;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

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
use Net::AFP::AccessRights;
use Net::AFP::ACL;
use Encode;                     # handle encoding/decoding strings
use Socket;                     # for socket related constants for
                                # parent/child IPC code
use Fcntl qw(:mode :DEFAULT :flock);
                                # for O_* (access mode) and S_* (permission
                                # mode) macros
use Data::Dumper;               # for diagnostic output when debugging is on
use Fuse qw(:all);              # Still need this for extended attribute
                                # related macros.
use POSIX qw(:errno_h !ENODATA :fcntl_h F_OK R_OK W_OK X_OK floor);
                                # Standard error codes, access() modes, etc.
use Time::HiRes qw(gettimeofday);
use URI::Escape;
use English qw(-no_match_vars);
use Log::Log4perl;
use Readonly;
use String::Escape qw(printable);
my $has_I18N__Langinfo = 0;
eval {
    require I18N::Langinfo;
    1;
} and do {
    $has_I18N__Langinfo = 1;
    I18N::Langinfo->import(qw(langinfo CODESET));
};

# FreeBSD oh-so-handily names this error code differently, so I'm going
# to cheat just slightly...
sub ENODATA() {
    return($OSNAME eq 'freebsd' ? Errno::ENOATTR() : Errno::ENODATA());
}

# We need UUID for a portable means to get a UUID to identify ourselves to
# the AFP server for FPAccess() calls; if it's there, it's definitely
# preferred.
my $has_UUID = 0;
eval { require UUID; 1; } and do { $has_UUID = 1; };

# Use a nice large blocksize to require fewer transactions with the server.
Readonly my $IO_BLKSIZE         => 0x40_000;

# Special magic extended attribute names to take advantage of certain
# AFP features.
Readonly my $ACL_XATTR          => 'system.afp_acl';
# This rejiggers the ACL data to/from the format that nfs4_setfacl and
# nfs4_getfacl like (for Linux). Pretty sure this won't work on FreeBSD
# et al., but I'm not finding anything to indicate that setfacl/getfacl
# on other OSes actually work with FUSE.
Readonly my $ACL_NFS4_XATTR     => 'system.nfs4_acl';
Readonly my $COMMENT_XATTR      => 'system.comment';

# }}}1

sub new { # {{{1
    my ($class, $url, $pw_cb, %opts) = @_;

    # By default, assume utf8 encoding. This is only used if we can't figure
    # it out using I18N::Langinfo, and the user doesn't override it.
    my $encoding = 'utf8';
    # If the appropriate module is available to us, try to figure out what
    # character set the system is using.
    if ($has_I18N__Langinfo) {
        $encoding = langinfo(CODESET());
    }
    my $obj = $class->SUPER::new();
    $obj->{topDirID}        = 2;
    $obj->{volID}           = undef;
    $obj->{DTRefNum}        = undef;
    $obj->{afpconn}         = undef;
    $obj->{volicon}         = undef;
    $obj->{_getattr_cache}  = {};
    $obj->{logger}          = Log::Log4perl->get_logger(__PACKAGE__);

    if (exists $opts{encoding}) {
        $encoding = $opts{encoding};
        delete $opts{encoding};
    }
    $obj->{local_encode} = find_encoding($encoding);
    if (not ref $obj->{local_encode}) {
        croak 'Encoding ' . $encoding . ' was not known';
    }

    my($session, %urlparms);
    my $callback = sub {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        my(%values) = @_;
        return &{$pw_cb}(@values{qw[username host password]});
    };
    my $srvinfo;
    my %connopts;
    if (exists $opts{aforder}) {
        $connopts{aforder} = $opts{aforder};
    }
    ($session, %urlparms) = do_afp_connect($callback, $url, \$srvinfo,
            %connopts);
    if (not ref $session or not $session->isa('Net::AFP')) {
        exit $session;
    }

    $obj->{volicon} = $srvinfo->{VolumeIcon};
    if (exists $opts{novolicon}) {
        $obj->{volicon} = undef;
    }

    if (not defined $urlparms{volume}) {
        $session->close();
        croak('Unable to extract volume from AFP URL');
    }
    $obj->{afpconn} = $session;

    # Since AFP presents pre-localized times for everything, we need to get
    # the server's time offset, and compute the difference between that and
    # our timestamp, to appropriately apply time localization.
    my $srvparms;
    my $rc = $obj->{afpconn}->FPGetSrvrParms(\$srvparms);
    if ($rc != $kFPNoErr) {
        $obj->disconnect();
        return EACCES;
    }

    # This is a bit hackish, but it seems to be the best way to make sure
    # that times are (most likely) consistent across mount sessions. Round
    # to the nearest half-hour.
    my $delta = time() - $srvparms->{ServerTime};
    my $neg = $delta < 0;
    $delta = abs($delta) / 1800.0;
    $delta = ($delta - int($delta) >= 0.5) ? ceil($delta) : floor($delta);
    $delta *= 1800;
    if ($neg) { $delta *= -1; }
    $obj->{timedelta} = $delta;

    $obj->{dotdothack} = 0;
    my $selfinfo;
    $obj->{afpconn}->FPGetUserInfo(0x1, 0, 0x3, \$selfinfo);
    # This is sort of a hack. Seems that instead of returning '0' as the
    # user ID from the FPGetUserInfo call, the AirPort Disk AFP server
    # tells us the user ID is 1. What is this crap. But anyway.
    if ($srvinfo->{MachineType} =~ m{\AAirPort}sm) {
        $selfinfo->{UserID} = 0;
        $obj->{dotdothack} = 1;
    }

    # Map UIDs and GIDs for the user we're mounting this for to the UID and
    # GID of the remote user. Also, establish maps of the local user's name
    # and primary group to the UUIDs for the remote user and primary group,
    # for ACL handling.
    my $uidmap = {};
    my $u_uuidmap = {};
    my $mapped_uid = $REAL_USER_ID;
    if (exists $opts{uid}) {
        $mapped_uid = int $opts{uid};
    }
    $uidmap->{$selfinfo->{UserID}} = $mapped_uid;
    $obj->{uidmap} = $uidmap;
    $obj->{uidmap_r} = { reverse %{$uidmap} };

    my $local_username = getpwuid $mapped_uid;
    if ($local_username) {
        my $u_uuid;
        $rc = $obj->{afpconn}->FPMapName($kUTF8NameToUserUUID,
                $local_username, \$u_uuid);
        if ($rc == $kFPNoErr) {
            $u_uuidmap->{$local_username} = $u_uuid;
        }
    }
    $obj->{u_uuidmap} = $u_uuidmap;
    $obj->{u_uuidmap_r} = { reverse %{$u_uuidmap} };

    my $gidmap = {};
    my $g_uuidmap = {};
    my $mapped_gid = (split m{\s+}sm, $REAL_GROUP_ID)[0];
    if (exists $opts{gid}) {
        $mapped_gid = int $opts{gid};
    }
    $gidmap->{$selfinfo->{UserID}} = $mapped_gid;
    $obj->{gidmap} = $gidmap;
    $obj->{gidmap_r} = { reverse %{$gidmap} };

    my $local_grpname = getgrgid $mapped_gid;
    if ($local_grpname) {
        my $g_uuid;
        $rc = $obj->{afpconn}->FPMapName($kUTF8NameToGroupUUID,
                $local_grpname, \$g_uuid);
        if ($rc == $kFPNoErr) {
            $g_uuidmap->{$local_grpname} = $g_uuid;
        }
    }
    $obj->{g_uuidmap} = $g_uuidmap;
    $obj->{g_uuidmap_r} = { reverse %{$g_uuidmap} };

    # Open the volume indicated at start time, and abort if the server
    # bitches at us.
    # open volume {{{2
    my $volinfo;
    $rc = $obj->{afpconn}->FPOpenVol($kFPVolAttributeBit |
            $kFPVolSignatureBit, $urlparms{volume}, undef,
            \$volinfo);
    if ($rc == $kFPAccessDenied) {
        # no volume password; does apple's AFP server even support volume
        # passwords anymore? I don't really know.
        $obj->{logger}->error('Server expected volume password');
        $obj->disconnect();
        return EACCES;
    }
    elsif ($rc == $kFPObjectNotFound || $rc == $kFPParamErr) {
        # Server didn't know the volume we asked for.
        $obj->{logger}->error(sub { sprintf q{Volume "%s" does not exist on server},
          $urlparms{volume} });
        $obj->disconnect();
        return ENODEV;
    }
    elsif ($rc != $kFPNoErr) {
        # Some other error occurred; if the docs are to be believed, this
        # should never happen unless we pass bad flags (coding error) or some
        # non-AFP-specific condition causes a failure (which is out of our
        # hands)...
        $obj->{logger}->error(sub { sprintf q{FPOpenVol failed with error %d (%s)},
          $rc, afp_strerror($rc) });
        $obj->disconnect();
        return ENODEV;
    }
    $obj->{logger}->debug(sub { Dumper($volinfo) });

    if ($volinfo->{Signature} == 3) {
        $obj->{logger}->error('Volume uses variable Directory IDs; not currently supported');
        $obj->disconnect();
        return EINVAL;
    }

    $obj->{volID} = $volinfo->{ID};
    # Copy out the attribute value, since there are some flags we should
    # really be checking in there (you know, for UTF8 support, extended
    # attributes, ACLs, things like that)...
    $obj->{volAttrs}    = $volinfo->{Attribute};

    $obj->{pathType}    = $kFPLongName; # AFP long names by default
    $obj->{pathFlag}    = $kFPLongNameBit;
    $obj->{pathkey}     = 'LongName';

    if ($obj->{volAttrs} & $kSupportsUTF8Names) {
        # If the remote volume does UTF8 names, then we'll go with that..
        $obj->{pathType}    = $kFPUTF8Name;
        $obj->{pathFlag}    = $kFPUTF8NameBit;
        $obj->{pathkey}     = 'UTF8Name';
    }

    $obj->{DForkLenFlag}    = $kFPDataForkLenBit;
    $obj->{RForkLenFlag}    = $kFPRsrcForkLenBit;
    $obj->{DForkLenKey}     = 'DataForkLen';
    $obj->{RForkLenKey}     = 'RsrcForkLen';
    $obj->{UseExtOps}       = 0;
    $obj->{ReadFn}          = 'Net::AFP::FPRead';
    $obj->{WriteFn}         = 'Net::AFP::FPWrite';
    $obj->{EnumFn}          = 'Net::AFP::FPEnumerate';
    # AFP prior to 2.0 doesn't provide any locking semantics, so just use
    # a bullshit empty function ref.
    $obj->{LockFn}          = sub { };
    $obj->{MaxReplySize}    = 0x7FFF;

    if (Net::AFP::Versions::CompareByVersionNum($obj->{afpconn}, 2, 0,
            $kFPVerAtLeast)) {
        $obj->{LockFn}          = 'Net::AFP::FPByteRangeLock';
    }

    # I *think* large file support entered the picture as of AFP 3.0...
    if (Net::AFP::Versions::CompareByVersionNum($obj->{afpconn}, 3, 0,
            $kFPVerAtLeast)) {
        $obj->{DForkLenFlag}    = $kFPExtDataForkLenBit;
        $obj->{RForkLenFlag}    = $kFPExtRsrcForkLenBit;
        $obj->{DForkLenKey}     = 'ExtDataForkLen';
        $obj->{RForkLenKey}     = 'ExtRsrcForkLen';
        $obj->{UseExtOps}       = 1;
        $obj->{ReadFn}          = 'Net::AFP::FPReadExt';
        $obj->{WriteFn}         = 'Net::AFP::FPWriteExt';
        $obj->{LockFn}          = 'Net::AFP::FPByteRangeLockExt';
        $obj->{EnumFn}          = 'Net::AFP::FPEnumerateExt';
    }

    if (Net::AFP::Versions::CompareByVersionNum($obj->{afpconn}, 3, 1,
            $kFPVerAtLeast)) {
        $obj->{EnumFn}          = 'Net::AFP::FPEnumerateExt2';
        $obj->{MaxReplySize}    = 0x3FFFF;
    }

    # Not checking the return code here. If this fails, $self->{DTRefNum}
    # won't be defined, so we don't need to worry about possible later
    # unpredictable failures due to this.
    $obj->{afpconn}->FPOpenDT($obj->{volID}, \$obj->{DTRefNum});

    if ($obj->{volAttrs} & $kSupportsACLs) {
        if ($has_UUID) {
            $obj->{client_uuid} = UUID::uuid();
        }
        else {
            $obj->{logger}->info(q{Need UUID class for full ACL } .
                    q{functionality, ACL checking disabled});
        }
    }
    # }}}2

    # If a subpath is defined, find the node ID for the directory, and use
    # that as the root; if the node isn't found or is not a directory, then
    # abort.
    # lookup node ID for subpath mount {{{2
    if (defined $urlparms{subpath}) {
        $obj->{logger}->debug(sub { sprintf q{Looking up directory "%s" as pivot } .
          q{point for root node}, $urlparms{subpath} });
        my $realdirpath = translate_path($urlparms{subpath}, $obj);
        my $dirbitmap = $kFPNodeIDBit;

        my $resp;
        ($rc, $resp) = $obj->{afpconn}->FPGetFileDirParms(
                VolumeID        => $obj->{volID},
                DirectoryID     => $obj->{topDirID},
                FileBitmap      => $dirbitmap,
                DirectoryBitmap => $dirbitmap,
                PathType        => $obj->{pathType},
                Pathname        => $realdirpath);

        if ($rc != $kFPNoErr or not exists $resp->{NodeID}) {
            $obj->{logger}->error('Specified directory not found');
            $obj->disconnect();
            return ENOENT;
        }

        if ($resp->{FileIsDir} != 1) {
            $obj->{logger}->error('Attempted to pivot mount root to non-directory');
            $obj->disconnect();
            return ENOTDIR;
        }
        $obj->{topDirID} = $resp->{NodeID};
        $obj->{logger}->debug(sub { sprintf q{Mount root node ID changed to %s},
          $obj->{topDirID} });
    } # }}}2

    # purify URL {{{2
    my $scrubbed_url = $urlparms{protocol} . q{:/};
    if ($urlparms{atalk_transport}) {
        $scrubbed_url .= $urlparms{atalk_transport};
    }
    $scrubbed_url .= q{/};
    if (defined $urlparms{username}) {
        $scrubbed_url .= uri_escape($urlparms{username}) . q{@};
    }
    if ($urlparms{host} =~ m{:}sm) {
        $scrubbed_url .= q{[} . $urlparms{host} . q{]};
    }
    else {
        $scrubbed_url .= uri_escape($urlparms{host});
    }
    if (defined $urlparms{port}) {
        $scrubbed_url .= q{:} . $urlparms{port};
    }
    $scrubbed_url .= q{/};
    if (defined $urlparms{volume}) {
        $scrubbed_url .= uri_escape($urlparms{volume});
        if (defined $urlparms{subpath}) {
            $scrubbed_url .= join q{/}, map { uri_escape($_) } split m{/}sm,
                    $urlparms{subpath};
        }
    }
    $_[1] = $scrubbed_url;
    # }}}2

    $obj->{callcount} = {};
    $obj->{metrics} = {
                         wr_maxsize     => 0,
                         wr_minsize     => 2 ** 31,
                         wr_totalsz     => 0,
                         wr_count       => 0,
                         wr_totaltime   => 0,
                         wr_maxtime     => 0,
                         wr_mintime     => 2 ** 31,
                       };

    return $obj;
} # }}}1

sub disconnect { # {{{1
    my ($self) = @_;

    if (defined $self->{afpconn}) {
        if (defined $self->{DTRefNum}) {
            $self->{afpconn}->FPCloseDT($self->{DTRefNum});
        }
        if (defined $self->{volID}) {
            $self->{afpconn}->FPCloseVol($self->{volID});
        }
        $self->{afpconn}->FPLogout();
        $self->{afpconn}->close();
    }
    return;
} # }}}1

sub getattr { # {{{1
    my ($self, $file) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s')},
      (caller 3)[3], $file });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);

    $self->{afpconn}->FPGetUserInfo(0x1, 0, 0x3, \my $selfinfo);
    my $uidmap = $self->{uidmap};
    my $gidmap = $self->{gidmap};
    if ($file eq '/._metrics') {
        my $timest = time;
        my @stat = ( # {{{2
            # device number (just make it 0, since it's not a real device)
            0,
            # inode number (node ID works fine)
            0,
            # permission mask
            S_IFREG | S_IRUSR | S_IRGRP | S_IROTH,
            # link count
            1,
            # UID number
            exists ${$uidmap}{$selfinfo->{UserID}} ? ${$uidmap}{$selfinfo->{UserID}} : $selfinfo->{UserID},
            # GID number
            exists ${$gidmap}{$selfinfo->{PrimaryGroupID}} ? ${$gidmap}{$selfinfo->{PrimaryGroupID}} : $selfinfo->{PrimaryGroupID},
            # device special major/minor number
            0,
            # file size in bytes
            4096,
            # last accessed time
            $timest,
            # data modified time
            $timest,
            # inode changed time
            $timest,
            # preferred block size
            $IO_BLKSIZE,
            # size in blocks
            1,
        ); # }}}2
        return @stat;
    }
    if ($self->{volicon} && $file eq '/.volicon.xpm') {
        my $timest = time;
        my @stat = ( # {{{2
            # device number (just make it 0, since it's not a real device)
            0,
            # inode number (node ID works fine)
            0,
            # permission mask
            S_IFREG | S_IRUSR | S_IRGRP | S_IROTH,
            # link count
            1,
            # UID number
            exists ${$uidmap}{$selfinfo->{UserID}} ? ${$uidmap}{$selfinfo->{UserID}} : $selfinfo->{UserID},
            # GID number
            exists ${$gidmap}{$selfinfo->{PrimaryGroupID}} ? ${$gidmap}{$selfinfo->{PrimaryGroupID}} : $selfinfo->{PrimaryGroupID},
            # device special major/minor number
            0,
            # file size in bytes
            length $self->{volicon},
            # last accessed time
            $timest,
            # data modified time
            $timest,
            # inode changed time
            $timest,
            # preferred block size
            $IO_BLKSIZE,
            # size in blocks
            int((length($self->{volicon}) + 4095) / 4096),
        ); # }}}2
        return @stat;
    }
    if ($self->{volicon} && $file eq '/autorun.inf') {
        my $timest = time;
        my @stat = ( # {{{2
            # device number (just make it 0, since it's not a real device)
            0,
            # inode number (node ID works fine)
            0,
            # permission mask
            S_IFREG | S_IRUSR | S_IRGRP | S_IROTH,
            # link count
            1,
            # UID number
            exists ${$uidmap}{$selfinfo->{UserID}} ? ${$uidmap}{$selfinfo->{UserID}} : $selfinfo->{UserID},
            # GID number
            exists ${$gidmap}{$selfinfo->{PrimaryGroupID}} ? ${$gidmap}{$selfinfo->{PrimaryGroupID}} : $selfinfo->{PrimaryGroupID},
            # device special major/minor number
            0,
            # file size in bytes
            29,
            # last accessed time
            $timest,
            # data modified time
            $timest,
            # inode changed time
            $timest,
            # preferred block size
            $IO_BLKSIZE,
            # size in blocks
            1,
        ); # }}}2
        return @stat;
    }
    my $filename = translate_path($file, $self);

    if (exists $self->{_getattr_cache}->{$filename}) {
        my $entry = $self->{_getattr_cache}->{$filename};
        if ($entry->{good_until} > time) {
            return @{$entry->{data}};
        }
        else {
            delete $self->{_getattr_cache}->{$filename};
        }
    }

    my ($rc, $resp) = $self->lookup_afp_entry($filename);
    return $rc if $rc;

    return -ENOENT() if $resp->{NodeID} == 0;

    my $uid = exists($resp->{UnixUID}) ? $resp->{UnixUID} : 0;
    if (exists $self->{uidmap}->{$uid}) {
        $uid = $self->{uidmap}->{$uid};
    }

    my $gid = exists($resp->{UnixGID}) ? $resp->{UnixGID} : 0;
    if (exists $self->{gidmap}->{$gid}) {
        $gid = $self->{gidmap}->{$gid};
    }

    # assemble stat record {{{2
    my @stat = (
        # device number (just make it 0, since it's not a real device)
        0,
        # inode number (node ID works fine)
        $resp->{NodeID},
        # permission mask
        exists($resp->{UnixPerms}) ? $resp->{UnixPerms} :
                ($resp->{FileIsDir} ? oct 40_755 : oct 100_644),
        # link count; not really technically correct (should just be the
        # number of subdirs), but there's not a convenient way to get just
        # that via AFP, other than walking the directory. for what it's
        # worth, it looks (empirically) like this is what apple's client
        # does too, instead of walking the dir.
        $resp->{FileIsDir} ? $resp->{OffspringCount} + 2 : 1,
        # UID number
        $uid,
        # GID number
        $gid,
        # device special major/minor number
        0,
        # file size in bytes
        $resp->{FileIsDir} ? 4096 : $resp->{$self->{DForkLenKey}},
        # last accessed time
        $resp->{ModDate} + $self->{timedelta},
        # data modified time
        $resp->{ModDate} + $self->{timedelta},
        # inode changed time
        $resp->{ModDate} + $self->{timedelta},
        #$resp->{CreateDate} + $self->{timedelta},
        # preferred block size
        $IO_BLKSIZE,
        # size in blocks
        $resp->{FileIsDir} ? 1 : int(($resp->{$self->{DForkLenKey}} - 1) / 512) + 1,
    ); # }}}2
    my $now = time;
    my $ttl;
    my $entryage = $now - $stat[9];
    if ($entryage < 50) {
        $ttl = 5;
    }
    elsif ($entryage >= 50 && $entryage < 600) {
        $ttl = int($entryage / 10);
    }
    else {
        $ttl = 60;
    }
    $self->{_getattr_cache}->{$filename} = {
            good_until  => $now + $ttl,
            data        => [ @stat ],
    };
    return(@stat);
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub readlink { # {{{1
    my ($self, $file) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s')},
      (caller 3)[3], $file });

    $self->{callcount}{(caller 0)[3]}++;

    # Classic MacOS' concept of an "alias", so far as I can tell, doesn't
    # really translate to the UNIX concept of a symlink; I might be able
    # to implement it later via file IDs, but until then, if UNIX permissions
    # aren't present, this won't work.
    return -EINVAL() if not $self->{volAttrs} & $kSupportsUnixPrivs;

    $file = $self->{local_encode}->decode($file);
    # Break the provided path down into a directory ID and filename.
    my $filename = translate_path($file, $self);

    # Get the UNIX privilege info for the file.
    my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            FileBitmap  => $kFPUnixPrivsBit,
            PathType    => $self->{pathType},
            Pathname    => $filename);
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EBADF()  if $rc != $kFPNoErr;

    # The UNIX privilege info is pretty universal, so just use the standard
    # macros to see if the permissions show it to be a symlink.
    # process symlink {{{2
    if (not S_ISLNK($resp->{UnixPerms})) {
        return -EINVAL();
    }

    # Now we have to open the "data fork" of this pseudo-file, read the
    # "contents" (a single line containing the path of the symbolic
    # link), and return that.
    my %sresp;
    ($rc, %sresp) = $self->{afpconn}->FPOpenFork(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            AccessMode  => $kFPAccessReadOnly,
            PathType    => $self->{pathType},
            Pathname    => $filename);
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EMFILE() if $rc == $kFPTooManyFilesOpen;
    return -EBADF()  if $rc != $kFPNoErr;

    my $linkpath;
    my $pos = 0;
    do {
        my $readtext;
        {
            ##no critic qw(ProhibitNoStrict)
            no strict qw(refs);
            ($rc, $readtext) = &{$self->{ReadFn}}($self->{afpconn},
                    OForkRefNum => $sresp{OForkRefNum},
                    Offset      => $pos,
                    ReqCount    => 1024);
        }
        return -EACCES() if $rc == $kFPAccessDenied;
        return -EINVAL() if $rc != $kFPNoErr and $rc != $kFPEOFErr;
        $linkpath .= ${$readtext};
    ##no critic qw(ProhibitPostfixControls)
    } while ($rc != $kFPEOFErr);
    $self->{afpconn}->FPCloseFork($sresp{OForkRefNum});
    if ($self->{dotdothack}) {
        # If this hack is active (for AirPort Disk volumes only,
        # currently), make sure any elements of the path that start
        # with .. get fixed up appropriately.
        my @parts = split m{/}sm, $linkpath;
        foreach (@parts) { s{^[.]![.][.](.)}{..$1}sm; }
        $linkpath = join q{/}, @parts;
    }
    return $self->{local_encode}->encode($linkpath);
    # }}}2

} # }}}1

sub getdir { # {{{1
    my ($self, $dirname) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(dirname = '%s')},
      (caller 3)[3], $dirname });

    $self->{callcount}{(caller 0)[3]}++;

    $dirname = $self->{local_encode}->decode($dirname);
    my $filename = translate_path($dirname, $self);
    my @fileslist = (q{.}, q{..});

    if ($dirname eq q{/}) {
        push @fileslist, '._metrics';
        if ($self->{volicon}) {
            push @fileslist, '.volicon.xpm', 'autorun.inf';
        }
    }

    if (defined $self->{client_uuid}) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_LIST_DIRECTORY,
                PathType    => $self->{pathType},
                Pathname    => $filename,
        );
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    my $resp;
    # Set the result set size limit; if there are more entries in the
    # directory, extra requests will have to be sent. Larger set sizes
    # mean less time spent waiting around for responses.
    my $setsize = 500;
    my %arglist = (
            VolumeID        => $self->{volID},
            DirectoryID     => $self->{topDirID},
            FileBitmap      => $self->{pathFlag},
            DirectoryBitmap => $self->{pathFlag},
            ReqCount        => $setsize,
            StartIndex      => 1,
            MaxReplySize    => $self->{MaxReplySize},
            PathType        => $self->{pathType},
            Pathname        => $filename,
          );
    my $rc = undef;
    # loop reading entries {{{2
    while (1) {
        {
            ##no critic qw(ProhibitNoStrict)
            no strict qw(refs);
            ($rc, $resp) = &{$self->{EnumFn}}($self->{afpconn}, %arglist);
        }

        last if $rc != $kFPNoErr;

        # Under some circumstances (no, this is not an error elsewhere in
        # my code, near as I can tell) on a second swipe, we'll get *one*
        # dirent back, which is a file we already got. that means that's
        # the end.
        if ($arglist{StartIndex} > 1 &&
                ($resp->[0]{$self->{pathkey}} eq $fileslist[-1])) {
            shift @{$resp};
            $arglist{StartIndex}++;
        }
        # anyone actually trying to readdir() gets the entries in reverse
        # order, for some odd reason; bug in FUSE driver/libfuse/Fuse module?
        foreach my $elem (@{$resp}) {
            my $name = $elem->{$self->{pathkey}};
            $name =~ tr{/}{:};
            if ($self->{dotdothack}) { $name =~ s{^[.]![.][.](.)}{..$1}sm; }
            push @fileslist, $self->{local_encode}->encode($name);
        }

        # Set up for a subsequent call to get directory entries.
        $arglist{StartIndex} += scalar @{$resp};
        undef $resp;
    }
    # }}}2
    if ($rc == $kFPObjectNotFound or $rc == $kFPNoErr) {
        return(@fileslist, 0);
    }
    return -EACCES()  if $rc == $kFPAccessDenied;
    return -ENOENT()  if $rc == $kFPDirNotFound;
    return -ENOTDIR() if $rc == $kFPObjectTypeErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EACCES();
}
# }}}1

sub mknod { # {{{1
    my ($self, $file, $mode, $devnum) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', mode = %x, } .
      q{devnum = %d)}, (caller 3)[3], $file, $mode, $devnum });

    $self->{callcount}{(caller 0)[3]}++;

    my $file_n = $file;
    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    if (not S_ISREG($mode)) {
        return -ENOTSUP();
    }

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($filename));
    return $rc if $rc;
    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_ADD_FILE,
                PathType    => $self->{pathType},
                Pathname    => path_parent($filename),
        );
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    $rc = $self->{afpconn}->FPCreateFile(
            VolumeID    => $self->{volID},
            DirectoryID => $resp->{NodeID},
            PathType    => $self->{pathType},
            Pathname    => node_name($filename),
    );
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EBUSY()  if $rc == $kFPFileBusy;
    return -EEXIST() if $rc == $kFPObjectExists;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    # Need to set the file mode (if possible) to the mode requested by
    # the call...
    return $self->chmod($file_n, S_IMODE($mode));
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub mkdir { # {{{1
    my ($self, $file, $mode) = @_;
    $self->{logger}->debug(sub {sprintf q{called %s(file = '%s', mode = %x)},
      (caller 3)[3], $file, $mode });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($filename));
    return $rc if $rc;
    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_ADD_SUBDIRECTORY,
                PathType    => $self->{pathType},
                Pathname    => path_parent($filename),
        );
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    $rc = $self->{afpconn}->FPCreateDir(
            VolumeID    => $self->{volID},
            DirectoryID => $resp->{NodeID},
            PathType    => $self->{pathType},
            Pathname    => node_name($filename),
    );
    if ($rc == $kFPNoErr) {
        # Set the mode on the directory to $mode.
        my $sresp;
        ($rc, $sresp) = $self->{afpconn}->FPGetFileDirParms(
                VolumeID        => $self->{volID},
                DirectoryID     => $resp->{NodeID},
                PathType        => $self->{pathType},
                Pathname        => node_name($filename),
                DirectoryBitmap => $kFPUnixPrivsBit,
        );
        return -EBADF() if $rc != $kFPNoErr;

        $rc = $self->{afpconn}->FPSetDirParms(
                VolumeID        => $self->{volID},
                DirectoryID     => $resp->{NodeID},
                PathType        => $self->{pathType},
                Pathname        => node_name($filename),
                Bitmap          => $kFPUnixPrivsBit,
                UnixPerms       => S_IFDIR | $mode,
                UnixUID         => $sresp->{UnixUID},
                UnixGID         => $sresp->{UnixGID},
                UnixAccessRights => $sresp->{UnixAccessRights},
        );
        return -EBADF() if $rc != $kFPNoErr;

        return 0;
    }
    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EPERM()  if $rc == $kFPFlatVol;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EEXIST() if $rc == $kFPObjectExists;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub unlink { # {{{1
    my ($self, $file) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s')},
      (caller 3)[3], $file });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($filename));
    return $rc if $rc;

    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_DELETE,
                PathType    => $self->{pathType},
                Pathname    => $filename,
        );
        return -EACCES() if $rc == $kFPAccessDenied;
        #return -ENOENT() if $rc == $kFPObjectNotFound;
        # HACK ALERT: Seems FPAccess() always follows links, so I can't
        # remove a dead symlink because the FPAccess() call always fails.
        # This works around that, but it's probably not the best solution.
        return -EBADF()  if $rc != $kFPNoErr and $rc != $kFPObjectNotFound
                and $rc != $kFPParamErr;
    }

    # don't have to worry about checking to ensure we're 'rm'ing a file;
    # this works for both, verifying that "unlink" is being invoked on a
    # non-directory is done elsewhere. also, we're referencing this sub
    # as the implementation for rmdir as well, which should work just fine
    # since the same backend call does both.
    $rc = $self->{afpconn}->FPDelete($self->{volID}, $resp->{NodeID},
            $self->{pathType}, node_name($filename));
    if ($rc == $kFPNoErr) {
        delete $self->{_getattr_cache}->{$filename};
        return 0;
    }
    return -EACCES()     if $rc == $kFPAccessDenied;
    return -EBUSY()      if $rc == $kFPFileBusy;
    return -EBUSY()      if $rc == $kFPObjectLocked;
    return -ENOENT()     if $rc == $kFPObjectNotFound;
    return -EISDIR()     if $rc == $kFPObjectTypeErr;
    return -EINVAL()     if $rc == $kFPParamErr;
    return -EROFS()      if $rc == $kFPVolLocked;
    return -ENOTEMPTY()  if $rc == $kFPDirNotEmpty;
    return -EBADF();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub rmdir { return Fuse::AFP::unlink(@_); }

# seems OS X 10.4 causes the newly created symlink to be locked, so once
# you create it, you can't remove it via AFP until you unmount the volume
# once. good work apple. :| doesn't happen on netatalk or OS X 10.5.
##no critic qw(ProhibitBuiltInHomonyms)
sub symlink { # {{{1
    my ($self, $target, $linkname) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(target = '%s', linkname = '%s')},
      (caller 3)[3], $target, $linkname });

    $self->{callcount}{(caller 0)[3]}++;

    return -EPERM() if not $self->{volAttrs} & $kSupportsUnixPrivs;

    $linkname = $self->{local_encode}->decode($linkname);
    my $filename = translate_path($linkname, $self);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($filename));
    return $rc if $rc;
    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_ADD_FILE,
                PathType    => $self->{pathType},
                Pathname    => path_parent($filename));
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    # Seems that the Airport Disk AFP server doesn't like having
    # FPCreateFile called with the full path; have to get the node ID
    # of the containing directory and just pass the node name.

    # create the target file first
    # create target file {{{2
    $rc = $self->{afpconn}->FPCreateFile(
            VolumeID    => $self->{volID},
            DirectoryID => $resp->{NodeID},
            PathType    => $self->{pathType},
            Pathname    => node_name($filename));
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EBUSY()  if $rc == $kFPFileBusy;
    return -EEXIST() if $rc == $kFPObjectExists;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;
    # }}}2

    # open the file, and write out the path given as the link target...
    # open and write link target {{{2
    my %sresp;
    ($rc, %sresp) = $self->{afpconn}->FPOpenFork(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            AccessMode  => $kFPAccessReadWrite,
            PathType    => $self->{pathType},
            Pathname    => $filename);
    return -EACCES()  if $rc == $kFPAccessDenied;
    return -ETXTBSY() if $rc == $kFPDenyConflict;
    return -ENOENT()  if $rc == $kFPObjectNotFound;
    return -EACCES()  if $rc == $kFPObjectLocked;
    return -EISDIR()  if $rc == $kFPObjectTypeErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EMFILE()  if $rc == $kFPTooManyFilesOpen;
    return -EROFS()   if $rc == $kFPVolLocked;
    return -EBADF()   if $rc != $kFPNoErr;
    if ($self->{dotdothack}) {
        # If this hack is active (for AirPort Disk volumes only, currently),
        # make sure any elements of the path that start with .. get fixed
        # up appropriately.
        my @parts = split m{/}sm, $target;
        foreach (@parts) { s{^[.][.](.)}{.!..$1}sm; }
        $target = join q{/}, @parts;
    }
    my $forkid = $sresp{OForkRefNum};

    my $lastwritten;
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, $lastwritten) = &{$self->{WriteFn}}($self->{afpconn},
                OForkRefNum => $forkid,
                Offset      => 0,
                ForkData    => \$target);
    }

    $self->{afpconn}->FPCloseFork($forkid);

    return -EACCES()  if $rc == $kFPAccessDenied;
    return -ENOSPC()  if $rc == $kFPDiskFull;
    return -ETXTBSY() if $rc == $kFPLockErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EBADF()   if $rc != $kFPNoErr;
    # }}}2

    # set finder info {{{2
    my $bitmap = $kFPFinderInfoBit | $kFPModDateBit;

    # apparently this is the magic to transmute a file into a symlink...
    $rc = $self->{afpconn}->FPSetFileParms(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            Bitmap      => $bitmap,
            PathType    => $self->{pathType},
            Pathname    => $filename,
            FinderInfo  => "slnkrhap\0\@" . "\0" x 22,
            ModDate     => time - $self->{timedelta});

    return 0         if $rc == $kFPNoErr;
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EBADF();
    # }}}2
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub rename { # {{{1
    my ($self, $oldname, $newname) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(oldname = '%s', newname = '%s')},
      (caller 3)[3], $oldname, $newname });

    $self->{callcount}{(caller 0)[3]}++;

    $oldname = $self->{local_encode}->decode($oldname);
    $newname = $self->{local_encode}->decode($newname);

    my $oldxlated = translate_path($oldname, $self);
    my $newxlated = translate_path($newname, $self);

    my $oldrealname = node_name($oldxlated);
    my $newrealname = node_name($newxlated);

    my ($rc, $old_stat) = $self->lookup_afp_entry($oldxlated);
    return $rc if $rc != $kFPNoErr;
    my $new_stat;
    ($rc, $new_stat) = $self->lookup_afp_entry(path_parent($newxlated));
    return $rc if $rc;

    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $old_stat->{ParentDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_DELETE,
                PathType    => $self->{pathType},
                Pathname    => $oldrealname);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;

        my $np_stat;
        ($rc, $np_stat) = $self->lookup_afp_entry(path_parent($newxlated));
        return $rc if $rc;

        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $np_stat->{NodeID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_ADD_FILE,
                PathType    => $self->{pathType},
                Pathname    => q{});
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    my %arglist = ( VolumeID            => $self->{volID},
                    SourceDirectoryID   => $old_stat->{ParentDirID},
                    DestDirectoryID     => $new_stat->{NodeID},
                    SourcePathType      => $self->{pathType},
                    SourcePathname      => $oldrealname,
                    DestPathType        => $self->{pathType},
                    DestPathname        => q{},
                    NewType             => $self->{pathType},
                    NewName             => $newrealname,
                  );
    $rc = $self->{afpconn}->FPMoveAndRename(%arglist);

    if ($rc == $kFPObjectExists) {
        $self->{afpconn}->FPDelete($self->{volID}, $new_stat->{NodeID},
                $self->{pathType}, $newrealname);
        $rc = $self->{afpconn}->FPMoveAndRename(%arglist);
    }
    return -EACCES() if $rc == $kFPAccessDenied;
    return -EINVAL() if $rc == $kFPCantMove;
    return -EBUSY()  if $rc == $kFPObjectLocked;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    delete $self->{_getattr_cache}->{$oldxlated};
    return 0;
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub link { # {{{1
    my ($self, $file, $target) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', target = %s)},
      (caller 3)[3], $file, $target });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOTSUP();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub chmod { # {{{1
    my ($self, $file, $mode) = @_;
    $self->{logger}->debug(sub {sprintf q{called %s(file = '%s', mode = %o)},
      (caller 3)[3], $file, $mode });

    $self->{callcount}{(caller 0)[3]}++;

    return -EINVAL() if not $self->{volAttrs} & $kSupportsUnixPrivs;

    my $filename = translate_path($self->{local_encode}->decode($file),
            $self);
    my ($rc, $resp) = $self->lookup_afp_entry($filename, 1);
    return $rc if $rc != $kFPNoErr;

    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_WRITE_ATTRIBUTES,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    $rc = $self->{afpconn}->FPSetFileDirParms(
            VolumeID            => $self->{volID},
            DirectoryID         => $self->{topDirID},
            Bitmap              => $kFPUnixPrivsBit,
            PathType            => $self->{pathType},
            Pathname            => $filename,
            UnixPerms           => $mode | S_IFMT($resp->{UnixPerms}),
            UnixUID             => $resp->{UnixUID},
            UnixGID             => $resp->{UnixGID},
            UnixAccessRights    => $resp->{UnixAccessRights});
    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    delete $self->{_getattr_cache}->{$filename};
    return 0;
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub chown { # {{{1
    my ($self, $file, $uid, $gid) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', uid = %d, } .
      q{gid = %d)}, (caller 3)[3], $file, $uid, $gid });

    $self->{callcount}{(caller 0)[3]}++;

    return -EINVAL() if not $self->{volAttrs} & $kSupportsUnixPrivs;

    my $filename = translate_path($self->{local_encode}->decode($file),
            $self);
    my ($rc, $resp) = $self->lookup_afp_entry($filename, 1);
    return $rc if $rc != $kFPNoErr;

    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_CHANGE_OWNER,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    if (exists $self->{uidmap_r}->{$uid}) {
        $uid = $self->{uidmap_r}->{$uid};
    }

    if (exists $self->{gidmap_r}->{$gid}) {
        $gid = $self->{gidmap_r}->{$gid};
    }

    $rc = $self->{afpconn}->FPSetFileDirParms(
            VolumeID            => $self->{volID},
            DirectoryID         => $self->{topDirID},
            Bitmap              => $kFPUnixPrivsBit,
            PathType            => $self->{pathType},
            Pathname            => $filename,
            UnixPerms           => $resp->{UnixPerms},
            UnixUID             => $uid,
            UnixGID             => $gid,
            UnixAccessRights    => $resp->{UnixAccessRights});
    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    delete $self->{_getattr_cache}->{$filename};
    return 0;
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub truncate { # {{{1
    my ($self, $file, $length) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', length = %d)},
      (caller 3)[3], $file, $length });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    if (defined $self->{client_uuid}) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_WRITE_DATA,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    my ($rc, %resp) = $self->{afpconn}->FPOpenFork(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            AccessMode  => $kFPAccessReadWrite,
            PathType    => $self->{pathType},
            Pathname    => $filename);
    return -EPERM()  if $rc == $kFPAccessDenied;
    return -EPERM()  if $rc == $kFPDenyConflict;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EPERM()  if $rc == $kFPObjectLocked;
    return -EISDIR() if $rc == $kFPObjectTypeErr;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EMFILE() if $rc == $kFPTooManyFilesOpen;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    $rc = $self->{afpconn}->FPSetForkParms($resp{OForkRefNum},
            $self->{DForkLenFlag}, $length);

    $self->{afpconn}->FPCloseFork($resp{OForkRefNum});

    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EPERM()  if $rc == $kFPLockErr;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    delete $self->{_getattr_cache}->{$filename};
    return 0;
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub utime { # {{{1
    my ($self, $file, $actime, $modtime) = @_;
    $self->{logger}->debug(sub {sprintf q{called %s(file = '%s', actime = %d, } .
      q{modtime = %d)}, (caller 3)[3], $file, $actime, $modtime });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    my $rc = $self->{afpconn}->FPSetFileDirParms(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            Bitmap      => $kFPModDateBit,
            #Bitmap      => $kFPCreateDateBit | $kFPModDateBit,
            PathType    => $self->{pathType},
            Pathname    => $filename,
            #CreateDate  => $actime - $self->{timedelta},
            ModDate     => $modtime - $self->{timedelta});
    if ($rc == $kFPNoErr) {
        delete $self->{_getattr_cache}->{$filename};
        return 0;
    }
    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub open { # {{{1
    my ($self, $file, $mode) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', mode = %x)},
      (caller 3)[3], $file, $mode });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    if ($file eq '/._metrics') {
        my $data = $self->generate_metrics_data();
        return(0, \$data);
    }
    if ($self->{volicon} && $file eq '/.volicon.xpm') {
        my $volicon = $self->{volicon};
        return(0, \$volicon);
    }
    if ($self->{volicon} && $file eq '/autorun.inf') {
        my $autorun_text = "[autorun]\nicon=\\.volicon.xpm\n";
        return(0, \$autorun_text);
    }

    my $filename = translate_path($file, $self);

    my $accmode = $mode & O_ACCMODE;
    if (defined $self->{client_uuid}) {
        my $reqacc = 0;
        if ($accmode == O_RDONLY || $accmode == O_RDWR) {
            $reqacc |= $KAUTH_VNODE_READ_DATA;
        }

        if ($accmode == O_WRONLY || $accmode == O_RDWR) {
            $reqacc |= $KAUTH_VNODE_WRITE_DATA;
        }

        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $reqacc,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    my $accessbitmap = $kFPAccessReadOnly;
    if ($accmode == O_RDWR) {
        $accessbitmap = $kFPAccessReadWrite;
    }
    elsif ($accmode == O_WRONLY) {
        # HACK: Thanks Apple. Way to, I don't know, know how to IMPLEMENT
        # YOUR OWN PROTOCOL. Seems with Airport Disk, if you open a file
        # write-only, and then, oh, try to WRITE TO IT, the writes then
        # fail. Wow. That makes so much sense!
        $accessbitmap = $kFPAccessReadWrite;
    }
    elsif ($accmode == O_RDONLY) {
        $accessbitmap = $kFPAccessReadOnly;
    }

    my($rc, %resp) = $self->{afpconn}->FPOpenFork(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            AccessMode  => $accessbitmap,
            PathType    => $self->{pathType},
            Pathname    => $filename);

    return(0, $resp{OForkRefNum})
                      if $rc == $kFPNoErr;
    return -EACCES()  if $rc == $kFPAccessDenied;
    return -ETXTBSY() if $rc == $kFPDenyConflict;
    return -ENOENT()  if $rc == $kFPObjectNotFound;
    return -EACCES()  if $rc == $kFPObjectLocked;
    # Yeah, this seems a little odd, but it appears to make more sense to
    # have the return code mapped this way.
    return -ENOENT()  if $rc == $kFPObjectTypeErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EMFILE()  if $rc == $kFPTooManyFilesOpen;
    return -EROFS()   if $rc == $kFPVolLocked;
    return -EBADF();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub read { # {{{1
    my ($self, $file, $len, $off, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', len = %d, } .
      q{off = %d, fh = %d)}, (caller 3)[3], $file || q{}, $len, $off,
      ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    if (ref $fh) {
        if ($off > length ${$fh}) {
            return q{};
        }
        if ($off + $len > length ${$fh}) {
            $len = length(${$fh}) - $off;
        }
        return substr ${$fh}, $off, $len;
    }

    my($rc, $resp);
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, $resp) = &{$self->{ReadFn}}($self->{afpconn},
                OForkRefNum => $fh,
                Offset      => $off,
                ReqCount    => $len);
    }
    return ${$resp}   if $rc == $kFPNoErr
            or $rc == $kFPEOFErr;
    return -EBADF()   if $rc == $kFPAccessDenied;
    return -ETXTBSY() if $rc == $kFPLockErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EBADF();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub write { # {{{1
    my ($self, $file, $offset, $fh) = @_[0,1,3,4];
    my $data_r = \$_[2];
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', data = %s, } .
      q{offset = %d, fh = %d)}, (caller 3)[3], $file || q{}, q{[data]}, $offset,
      ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;
    my $filename = translate_path($file, $self);

    return -EBADF() if ref $fh;

    my $ts_start = gettimeofday();
    my($rc, $lastwritten);
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, $lastwritten) = &{$self->{WriteFn}}($self->{afpconn},
                OForkRefNum => $fh,
                Offset      => $offset,
                ReqCount    => length(${$data_r}),
                ForkData    => $data_r);
    }
    my $wr_time = gettimeofday() - $ts_start;

    return -EACCES()     if $rc == $kFPAccessDenied;
    return -ENOSPC()     if $rc == $kFPDiskFull;
    return -ETXTBSY()    if $rc == $kFPLockErr;
    return -EINVAL()     if $rc == $kFPParamErr;
    return -EBADF()      if $rc != $kFPNoErr;

    $self->{metrics}->{wr_totaltime} += $wr_time;
    $self->{metrics}->{wr_count}++;
    if ($wr_time > $self->{metrics}->{wr_maxtime}) {
        $self->{metrics}->{wr_maxtime} = $wr_time;
    }
    if ($wr_time < $self->{metrics}->{wr_mintime}) {
        $self->{metrics}->{wr_mintime} = $wr_time;
    }

    my $wr_size = $lastwritten - $offset;
    $self->{metrics}->{wr_totalsz} += $wr_size;
    if ($wr_size > $self->{metrics}->{wr_maxsize}) {
        $self->{metrics}->{wr_maxsize} = $wr_size;
    }
    if ($wr_size < $self->{metrics}->{wr_minsize}) {
        $self->{metrics}->{wr_minsize} = $wr_size;
    }

    delete $self->{_getattr_cache}->{$filename};
    return $wr_size;
} # }}}1

sub statfs { # {{{1
    my ($self) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s()}, (caller 3)[3] });

    $self->{callcount}{(caller 0)[3]}++;

    my $volbitmap;
    my $bf_key;
    my $bt_key;
    my $blocksize = 512;
    if ($self->{UseExtOps}) {
        $volbitmap |= $kFPVolExtBytesFreeBit | $kFPVolExtBytesTotalBit |
                      $kFPVolBlockSizeBit;
        $bf_key = 'ExtBytesFree';
        $bt_key = 'ExtBytesTotal';
    }
    else {
        $volbitmap |= $kFPVolBytesFreeBit | $kFPVolBytesTotalBit;
        $bf_key = 'BytesFree';
        $bt_key = 'BytesTotal';
    }
    my $resp;
    my $rc = $self->{afpconn}->FPGetVolParms($self->{volID}, $volbitmap,
            \$resp);
    if (exists $resp->{BlockSize}) {
        $blocksize = $resp->{BlockSize};
    }
    my @statinfo = (
            # namelen (?)
            255,
            # file count; not really (we're lying here), but afp doesn't
            # keep an "existing files" count
            int($resp->{$bt_key} / $blocksize),
            # files_free count; lying again, but afp doesn't have a concept
            # of "free inodes" either, it's not aware of such stuff
            int($resp->{$bf_key} / $blocksize),
            # total blocks
            int($resp->{$bt_key} / $blocksize),
            # free blocks
            int($resp->{$bf_key} / $blocksize),
            # block size
            $blocksize,
    );
    return(@statinfo);
} # }}}1

sub flush { # {{{1
    my ($self, $file, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', fh = %d)},
      (caller 3)[3], $file || q{}, ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return 0 if ref $fh;

    my $rc = $self->{afpconn}->FPFlushFork($fh);

    return -EBADF() if $rc != $kFPNoErr;
    return 0;
} # }}}1

sub release { # {{{1
    my ($self, $file, $mode, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', mode = %x, } .
      q{fh = %d)}, (caller 3)[3], $file || q{}, $mode, ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return 0 if ref $fh;

    $self->{afpconn}->FPCloseFork($fh);
    return 0;
} # }}}1

sub fsync { # {{{1
    my ($self, $file, $flags, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', flags = %x, } .
      q{fh = %d)}, (caller 3)[3], $file || q{}, $flags, ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return 0 if ref $fh;

    if (not $flags) {
        return $self->flush($file, $fh);
    }
    return 0;
} # }}}1

sub setxattr { # {{{1
    my ($self, $file, $attr, $value, $flags) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', attr = '%s', } .
      q{value = '%s', flags = %x)}, (caller 3)[3], $file, $attr, printable($value),
      $flags });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);
    $attr = $self->{local_encode}->decode($attr);

    # handle ACL xattr {{{2
    if (($attr eq $ACL_XATTR || $attr eq $ACL_NFS4_XATTR)
            && defined($self->{client_uuid})) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_WRITE_SECURITY,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;

        # if either of the flags is present, apply extra checking for the
        # presence of an ACL.
        if ($flags) {
            my %resp;
            ($rc, %resp) = $self->{afpconn}->FPGetACL(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            if ($flags & XATTR_CREATE) {
                return -EEXIST()  if $resp{Bitmap} & $kFileSec_ACL;
            }
            elsif ($flags & XATTR_REPLACE) {
                return -ENODATA() if not $resp{Bitmap} & $kFileSec_ACL;
            }
        }

        my $acl;
        my $rv;
        if ($attr eq $ACL_XATTR) {
            # Format is AFP ACL (well, _my_ serialization of it anyway).
            $rv = $self->acl_from_xattr($value, \$acl);
        }
        elsif ($attr eq $ACL_NFS4_XATTR) {
            # Format is NFSv4 ACL.
            $rv = $self->acl_from_nfsv4_xattr($value, \$acl, $filename);
        }

        if ($rv != 0) {
            return $rv;
        }
        # send the ACL on to the AFP server.
        $rc = $self->{afpconn}->FPSetACL(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                Bitmap      => $kFileSec_ACL,
                PathType    => $self->{pathType},
                Pathname    => $filename,
                %{$acl});
        return -EACCES()  if $rc == $kFPAccessDenied;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        return -EBADF()   if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq $COMMENT_XATTR && defined $self->{DTRefNum}) {
        # If either of the flags is present, apply extra checking for the
        # presence of a finder comment.
        if ($flags) {
            my($rc, $comment) = $self->{afpconn}->FPGetComment(
                    DTRefNum    => $self->{DTRefNum},
                    DirectoryID => $self->{topDirID},
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            if ($flags & XATTR_CREATE) {
                return -EEXIST()
                        if $rc == $kFPItemNotFound;
            }
            elsif ($flags & XATTR_REPLACE) {
                return -ENODATA()
                        if $rc != $kFPItemNotFound;
            }
        }
        my $rc = $self->{afpconn}->FPAddComment(
                DTRefNum    => $self->{DTRefNum},
                DirectoryID => $self->{topDirID},
                PathType    => $self->{pathType},
                Pathname    => $filename,
                Comment     => $value);
        return -EACCES()  if $rc == $kFPAccessDenied;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        return -ENOTSUP() if $rc == $kFPCallNotSupported;
        return -EBADF()   if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ m{^user[.]}sm or $OSNAME eq 'darwin') {
        if ($OSNAME ne 'darwin') {
            $attr =~ s{^user[.]}{}sm;
        }

        if ($attr eq 'com.apple.FinderInfo' and
                not ($self->{volAttrs} & $kSupportsExtAttrs)) {
            # If FinderInfo is already set to something (there's always data
            # there, but I'm interpreting "existence" to mean "data is there
            # and it's something that's not 32 bytes of 0"), apply special
            # handling for the XATTR_{CREATE,REPLACE} cases.
            if ($flags) {
                my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
                        VolumeID        => $self->{volID},
                        DirectoryID     => $self->{topDirID},
                        FileBitmap      => $kFPFinderInfoBit,
                        DirectoryBitmap => $kFPFinderInfoBit,
                        PathType        => $self->{pathType},
                        Pathname        => $filename);
                return -EPERM()   if $rc == $kFPAccessDenied;
                return -ENOENT()  if $rc == $kFPObjectNotFound;
                return -EBADF()   if $rc != $kFPNoErr;

                if ($flags & XATTR_CREATE) {
                    return -EEXIST()  if $resp->{FinderData} ne "\0" x 32;
                }
                elsif ($flags & XATTR_REPLACE) {
                    return -ENODATA() if $resp->{FinderData} eq "\0" x 32;
                }
            }
            my $rc = $self->{afpconn}->FPSetFileDirParms(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    Bitmap      => $kFPFinderInfoBit,
                    FinderInfo  => $value,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EPERM()  if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EROFS()  if $rc == $kFPVolLocked;
            return 0;
        }
        elsif ($attr eq 'com.apple.ResourceFork') {
            # Apply special handling for XATTR_{CREATE,REPLACE} cases. It's
            # more clear-cut if there's "something" or "nothing" here, since
            # if there's "something", the resource fork length will be
            # non-zero.
            if ($flags) {
                my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
                        VolumeID    => $self->{volID},
                        DirectoryID => $self->{topDirID},
                        FileBitmap  => $self->{RForkLenFlag},
                        PathType    => $self->{pathType},
                        Pathname    => $filename);
                return -EPERM()   if $rc == $kFPAccessDenied;
                return -ENOENT()  if $rc == $kFPObjectNotFound;
                return -EBADF()   if $rc != $kFPNoErr;
                return -EISDIR()  if $resp->{FileIsDir} == 1;

                if ($flags & XATTR_CREATE) {
                    return -EEXIST()  if $resp->{$self->{RForkLenKey}} != 0;
                }
                elsif ($flags & XATTR_REPLACE) {
                    return -ENODATA() if $resp->{$self->{RForkLenKey}} == 0;
                }
            }
            my ($rc, %resp) = $self->{afpconn}->FPOpenFork(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    AccessMode  => $kFPAccessReadWrite,
                    Flag        => $kFPResourceDataFlag,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EISDIR() if $rc == $kFPObjectTypeErr;
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EMFILE() if $rc == $kFPTooManyFilesOpen;
            return -EBADF()  if $rc != $kFPNoErr;

            $rc = $self->{afpconn}->FPSetForkParms($resp{OForkRefNum},
                    $self->{RForkLenFlag}, 0);
            return -EPERM()  if $rc == $kFPAccessDenied;
            return -ENOSPC() if $rc == $kFPDiskFull;
            return -EPERM()  if $rc == $kFPLockErr;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EROFS()  if $rc == $kFPVolLocked;
            return -EBADF()  if $rc != $kFPNoErr;

            {
                ##no critic qw(ProhibitNoStrict)
                no strict qw(refs);
                $rc = &{$self->{WriteFn}}($self->{afpconn},
                        OForkRefNum   => $resp{OForkRefNum},
                        Offset        => 0,
                        ReqCount      => length($value),
                        ForkData      => \$value);
            }
            return -EACCES()  if $rc == $kFPAccessDenied;
            return -ENOSPC()  if $rc == $kFPDiskFull;
            return -ETXTBSY() if $rc == $kFPLockErr;
            return -EINVAL()  if $rc == $kFPParamErr;
            return -EBADF()   if $rc != $kFPNoErr;

            $self->{afpconn}->FPCloseFork($resp{OForkRefNum});

            return 0;
        }
        return -ENOTSUP() if not $self->{volAttrs} & $kSupportsExtAttrs;

        if (defined $self->{client_uuid}) {
            my $rc = $self->{afpconn}->FPAccess(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    UUID        => $self->{client_uuid},
                    ReqAccess   => $KAUTH_VNODE_WRITE_EXTATTRIBUTES,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EBADF()  if $rc != $kFPNoErr;
        }

        # Set flags to pass to the server for special handling of the
        # extended attribute.
        my $xaflags = $kXAttrNoFollow;
        if ($flags & XATTR_CREATE) {
            $xaflags |= $kXAttrCreate;
        }
        if ($flags & XATTR_REPLACE) {
            $xaflags |= $kXAttrReplace;
        }
        # Send the set request to the server.
        my $rc = $self->{afpconn}->FPSetExtAttr(
                VolumeID        => $self->{volID},
                DirectoryID     => $self->{topDirID},
                Bitmap          => $xaflags,
                PathType        => $self->{pathType},
                Pathname        => $filename,
                Name            => $attr,
                AttributeData   => $value);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        # hopefully this is correct...
        if ($rc == $kFPMiscErr) {
            return -EEXIST()  if $flags & XATTR_CREATE;
            return -ENODATA() if $flags & XATTR_REPLACE;
        }
        return -EBADF()  if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    return -ENOTSUP();
} # }}}1

sub getxattr { # {{{1
    my ($self, $file, $attr) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', attr = '%s')},
      (caller 3)[3], $file, $attr});

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);
    $attr = $self->{local_encode}->decode($attr);
    # handle ACL xattr {{{2
    if (($attr eq $ACL_XATTR || $attr eq $ACL_NFS4_XATTR) &&
            defined($self->{client_uuid})) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_READ_SECURITY,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -ENODATA() if $rc == $kFPAccessDenied;
        return -ENODATA() if $rc == $kFPObjectNotFound;
        return -EBADF()   if $rc != $kFPNoErr;

        # get the ACL from the server.
        my %resp;
        ($rc, %resp) = $self->{afpconn}->FPGetACL(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -ENODATA() if $rc == $kFPAccessDenied;
        return -ENODATA() if $rc == $kFPObjectNotFound;
        return -EBADF()   if $rc != $kFPNoErr;
        # Check to see if the server actually sent us an ACL in its
        # response; if the file has no ACL, it'll just not return one.
        if ($resp{Bitmap} & $kFileSec_ACL) {
            if ($attr eq $ACL_XATTR) {
                # Format is AFP ACL (well, _my_ serialization of it anyway).
                return $self->acl_to_xattr(\%resp);
            }
            elsif ($attr eq $ACL_NFS4_XATTR) {
                # Format is NFSv4 ACL.
                return $self->acl_to_nfsv4_xattr(\%resp, $filename);
            }
        }
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq $COMMENT_XATTR && defined $self->{DTRefNum}) {
        # If the desktop DB was opened, then try getting the finder comment
        # for the file. If one is present, return it.
        my($rc, $comment) = $self->{afpconn}->FPGetComment(
                DTRefNum    => $self->{DTRefNum},
                DirectoryID => $self->{topDirID},
                PathType    => $self->{pathType},
                Pathname    => $filename);
        if ($rc == $kFPNoErr and defined $comment) {
            return $comment;
        }
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ m{^user[.]}sm || $OSNAME eq 'darwin') {
        if ($OSNAME ne 'darwin') {
            $attr =~ s{^user[.]}{}sm;
        }

        if ($attr eq 'com.apple.FinderInfo' and
                not ($self->{volAttrs} & $kSupportsExtAttrs)) {
            my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
                    VolumeID        => $self->{volID},
                    DirectoryID     => $self->{topDirID},
                    FileBitmap      => $kFPFinderInfoBit,
                    DirectoryBitmap => $kFPFinderInfoBit,
                    PathType        => $self->{pathType},
                    Pathname        => $filename);
            return -EPERM()   if $rc == $kFPAccessDenied;
            return -ENOENT()  if $rc == $kFPObjectNotFound;
            return -EBADF()   if $rc != $kFPNoErr;
            return "\0" x 32 if not exists $resp->{FinderInfo};
            my $finfo = $resp->{FinderInfo};
            $finfo .= "\0" x (32 - length $finfo);
            return $resp->{FinderInfo};
        }
        elsif ($attr eq 'com.apple.ResourceFork') {
            my($rc, $resp) = $self->{afpconn}->FPGetFileParms(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    Bitmap      => $self->{RForkLenFlag},
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EPERM()   if $rc == $kFPAccessDenied;
            return -ENOENT()  if $rc == $kFPObjectNotFound;
            return -EBADF()   if $rc != $kFPNoErr;
            my $rforklen = $resp->{$self->{RForkLenKey}};

            my %resp;
            ($rc, %resp) = $self->{afpconn}->FPOpenFork(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    AccessMode  => $kFPAccessReadOnly,
                    Flag        => $kFPResourceDataFlag,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EMFILE() if $rc == $kFPTooManyFilesOpen;
            return -EBADF()  if $rc != $kFPNoErr;

            my $readtext;
            {
                ##no critic qw(ProhibitNoStrict)
                no strict qw(refs);
                ($rc, $readtext) = &{$self->{ReadFn}}($self->{afpconn},
                        OForkRefNum => $resp{OForkRefNum},
                        Offset      => 0,
                        ReqCount    => $rforklen);
            }
            return -EACCES() if $rc == $kFPAccessDenied;
            return -EINVAL() if $rc != $kFPNoErr and $rc != $kFPEOFErr;

            $self->{afpconn}->FPCloseFork($resp{OForkRefNum});

            return ${$readtext};
        }
        return -ENOTSUP() if not $self->{volAttrs} & $kSupportsExtAttrs;

        if (defined $self->{client_uuid}) {
            my $rc = $self->{afpconn}->FPAccess(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    UUID        => $self->{client_uuid},
                    ReqAccess   => $KAUTH_VNODE_READ_EXTATTRIBUTES,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EPERM()   if $rc == $kFPAccessDenied;
            return -ENOENT()  if $rc == $kFPObjectNotFound;
            return -EBADF()   if $rc != $kFPNoErr;
        }

        my %xaopts = (
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                Bitmap      => $kXAttrNoFollow,
                PathType    => $self->{pathType},
                Pathname    => $filename,
                Name        => $attr,
        );

        # Ask the server for the length of the extended attribute data.
        my($rc, %resp) = $self->{afpconn}->FPGetExtAttr(%xaopts);
        return -EPERM()   if $rc == $kFPAccessDenied;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        # hopefully this is correct...
        return -ENODATA() if $rc == $kFPParamErr;
        return -EBADF()   if $rc != $kFPNoErr;

        my $dlen = $resp{DataLength};
        # Get the real data from the server. Add 6 bytes to the length to
        # cover the bitmap and length values.
        ($rc, %resp) = $self->{afpconn}->FPGetExtAttr(%xaopts,
                MaxReplySize    => $dlen + 6);

        if (defined $resp{AttributeData} &&
                $resp{AttributeData} ne q{}) {
            return $resp{AttributeData};
        }
    } # }}}2
    return -ENOTSUP();
} # }}}1

sub listxattr { # {{{1
    my ($self, $file) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s')},
      (caller 3)[3], $file });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOTSUP() if not $self->{volAttrs} & $kSupportsExtAttrs;
    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    my @attrs;

    # general xattr handling {{{2
    if ($self->{volAttrs} & $kSupportsExtAttrs) {
        if (defined $self->{client_uuid}) {
            my $rc = $self->{afpconn}->FPAccess(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    UUID        => $self->{client_uuid},
                    ReqAccess   => $KAUTH_VNODE_READ_EXTATTRIBUTES,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EBADF()  if $rc != $kFPNoErr;
        }

        my %xaopts = (
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                Bitmap      => $kXAttrNoFollow,
                PathType    => $self->{pathType},
                Pathname    => $filename,
        );

        # Ask the server for the length of the extended attribute list.
        my ($rc, %resp) = $self->{afpconn}->FPListExtAttrs(%xaopts);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;

        my $dlen = $resp{DataLength};
        # Get the real data from the server. Add 6 bytes to the length to
        # cover the bitmap and length values.
        ($rc, %resp) = $self->{afpconn}->FPListExtAttrs(%xaopts,
                MaxReplySize    => $dlen + 6);
        @attrs = @{$resp{AttributeNames}};
    } # }}}2

    my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID        => $self->{volID},
            DirectoryID     => $self->{topDirID},
#            FileBitmap      => $self->{RForkLenFlag},
            FileBitmap      => $kFPFinderInfoBit | $self->{RForkLenFlag},
            DirectoryBitmap => $kFPFinderInfoBit,
            PathType        => $self->{pathType},
            Pathname        => $filename);

    if (not ($self->{volAttrs} & $kSupportsExtAttrs)
            and exists($resp->{FinderInfo})
            and $resp->{FinderInfo} ne "\0" x 32) {
        push @attrs, 'com.apple.FinderInfo';
    }

    if (exists($resp->{$self->{RForkLenKey}}) and
            $resp->{$self->{RForkLenKey}} > 0) {
        push @attrs, 'com.apple.ResourceFork';
    }

    if ($OSNAME ne 'darwin') {
        @attrs = map { 'user.' . $_ } @attrs;
    }

    # Try getting the ACL for the indicated file; if there's an ACL
    # present, then include the special name in the list of extended
    # attributes.
    # handle ACL xattr {{{2
    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_READ_SECURITY,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;

        my %resp;
        ($rc, %resp) = $self->{afpconn}->FPGetACL(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                PathType    => $self->{pathType},
                Pathname    => $filename);
        if ($rc == $kFPNoErr && ($resp{Bitmap} & $kFileSec_ACL)) {
            push @attrs, $ACL_XATTR;
        }
        push @attrs, $ACL_NFS4_XATTR;
    } # }}}2
    # If the desktop DB was opened (should have been...), check for a
    # finder comment on the file.
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    if (defined $self->{DTRefNum}) {
        my $comment;
        ($rc, $comment) = $self->{afpconn}->FPGetComment(
                DTRefNum    => $self->{DTRefNum},
                DirectoryID => $self->{topDirID},
                PathType    => $self->{pathType},
                Pathname    => $filename);
        if ($rc == $kFPNoErr and defined $comment) {
            push @attrs, $COMMENT_XATTR;
        }
    } # }}}2
    return(@attrs, 0);
} # }}}1

sub removexattr { # {{{1
    my ($self, $file, $attr) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', attr = '%s')},
      (caller 3)[3], $file, $attr });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);
    $attr = $self->{local_encode}->decode($attr);
    # handle ACL xattr {{{2
    if (($attr eq $ACL_XATTR || $attr eq $ACL_NFS4_XATTR) &&
            defined($self->{client_uuid})) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_WRITE_SECURITY,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;

        # Remove the ACL from the indicated file.
        $rc = $self->{afpconn}->FPSetACL(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                Bitmap      => $kFileSec_REMOVEACL,
                PathType    => $self->{pathType},
                Pathname    => $filename);

        return -EACCES()  if $rc == $kFPAccessDenied;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        return -EBADF()   if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    # handle comment xattr {{{2
    # comment stuff is deprecated as of AFP 3.3...
    elsif ($attr eq $COMMENT_XATTR and defined $self->{DTRefNum}) {
        # Remove the finder comment, if one is present.
        my $rc = $self->{afpconn}->FPRemoveComment($self->{DTRefNum},
                $self->{topDirID}, $self->{pathType}, $filename);
        return -EACCES()  if $rc == $kFPAccessDenied;
        return -ENODATA() if $rc == $kFPItemNotFound;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        return -EBADF()   if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    # general xattr handling {{{2
    elsif ($attr =~ m{^user[.]}sm or $OSNAME eq 'darwin') {
        if ($OSNAME ne 'darwin') {
            $attr =~ s{^user[.]}{}sm;
        }

        if ($attr eq 'com.apple.FinderInfo' and
                not ($self->{volAttrs} & $kSupportsExtAttrs)) {
            my $rc = $self->{afpconn}->FPSetFileDirParms(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    Bitmap      => $kFPFinderInfoBit,
                    FinderInfo  => "\0" x 32,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EPERM()  if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EROFS()  if $rc == $kFPVolLocked;
            return -EBADF()  if $rc != $kFPNoErr;
            return 0;
        }
        elsif ($attr eq 'com.apple.ResourceFork') {
            my ($rc, %resp) = $self->{afpconn}->FPOpenFork(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    AccessMode  => $kFPAccessReadWrite,
                    Flag        => $kFPResourceDataFlag,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EMFILE() if $rc == $kFPTooManyFilesOpen;
            return -EBADF()  if $rc != $kFPNoErr;

            $rc = $self->{afpconn}->FPSetForkParms($resp{OForkRefNum},
                    $self->{RForkLenFlag}, 0);

            $self->{afpconn}->FPCloseFork($resp{OForkRefNum});

            return -EPERM()  if $rc == $kFPAccessDenied;
            return -ENOSPC() if $rc == $kFPDiskFull;
            return -EPERM()  if $rc == $kFPLockErr;
            return -EINVAL() if $rc == $kFPParamErr;
            return -EROFS()  if $rc == $kFPVolLocked;
            return -EBADF()  if $rc != $kFPNoErr;

            return 0;
        }
        return -ENOTSUP() if not $self->{volAttrs} & $kSupportsExtAttrs;
        if (defined $self->{client_uuid}) {
            my $rc = $self->{afpconn}->FPAccess(
                    VolumeID    => $self->{volID},
                    DirectoryID => $self->{topDirID},
                    UUID        => $self->{client_uuid},
                    ReqAccess   => $KAUTH_VNODE_WRITE_EXTATTRIBUTES,
                    PathType    => $self->{pathType},
                    Pathname    => $filename);
            return -EACCES() if $rc == $kFPAccessDenied;
            return -ENOENT() if $rc == $kFPObjectNotFound;
            return -EBADF()  if $rc != $kFPNoErr;
        }

        # Remove the requested extended attribute from the indicated file.
        my $rc = $self->{afpconn}->FPRemoveExtAttr(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                Bitmap      => $kXAttrNoFollow,
                PathType    => $self->{pathType},
                Pathname    => $filename,
                Name        => $attr);
        return -EACCES()  if $rc == $kFPAccessDenied;
        return -ENOENT()  if $rc == $kFPObjectNotFound;
        # hopefully this is correct...
        return -ENODATA() if $rc == $kFPParamErr;
        return -EBADF()   if $rc != $kFPNoErr;
        return 0;
    } # }}}2
    return -ENODATA();
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub opendir { # {{{1
    my ($self, $dirname) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(dirname = '%s')},
      (caller 3)[3], $dirname });

    $self->{callcount}{(caller 0)[3]}++;

    $dirname = $self->{local_encode}->decode($dirname);
    my $filename = translate_path($dirname, $self);

    if (defined $self->{client_uuid}) {
        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_LIST_DIRECTORY,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    my ($rc, $cdir) = $self->lookup_afp_entry($filename);
    return $rc if $rc;
    return(0, $cdir->{NodeID});
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub readdir { # {{{1
    my ($self, $dirname, $offset, $dh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(dirname = '%s', } .
      q{offset = %d, dh = %d)}, (caller 3)[3], $dirname || q{}, $offset, $dh });

    $self->{callcount}{(caller 0)[3]}++;

    my @fileslist;

    # Set the result set size limit; if there are more entries in the
    # directory, extra requests will have to be sent. Larger set sizes
    # mean less time spent waiting around for responses.
    my $entrycount = 100;

    # Add '.' and '..' entries {{{2
    if (not $offset) {
        # If offset is 0, this is the first request, so '.' and '..' should
        # definitely be passed
        push @fileslist, [++$offset, q{.}], [++$offset, q{..}];
        $entrycount -= 2;

        if ($self->{topDirID} == $dh) {
            $entrycount -= 1;
            push @fileslist, [++$offset, '._metrics'];
            if ($self->{volicon}) {
                $entrycount -= 2;
                push @fileslist, [++$offset, '.volicon.xpm'],
                                 [++$offset, 'autorun.inf'];
            }
        }
    } # }}}2

    my $bitmap = $self->{pathFlag};

    my $delta = 2;
    if ($self->{topDirID} == $dh) {
        $delta += 1;
        if ($self->{volicon}) {
            $delta += 2;
        }
    }
    # Request entry list from server {{{2
    my($rc, $resp);
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, $resp) = &{$self->{EnumFn}}($self->{afpconn},
                        VolumeID        => $self->{volID},
                        DirectoryID     => $dh,
                        FileBitmap      => $bitmap,
                        DirectoryBitmap => $bitmap,
                        ReqCount        => $entrycount,
                        StartIndex      => $offset - $delta + 1,
                        MaxReplySize    => $self->{MaxReplySize},
                        PathType        => $self->{pathType},
                        Pathname        => q{});
    }
    return -EACCES()  if $rc == $kFPAccessDenied;
    return -ENOENT()  if $rc == $kFPDirNotFound;
    return -ENOTDIR() if $rc == $kFPObjectTypeErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EACCES()  if $rc != $kFPNoErr and $rc != $kFPObjectNotFound;
    # }}}2

    # Process entries {{{2
    my $name;
    foreach my $ent (@{$resp}) {
        ($name = $ent->{$self->{pathkey}}) =~ tr{/}{:};
        if ($self->{dotdothack}) { $name =~ s{^[.]![.][.](.)}{..$1}sm; }
        push @fileslist, [++$offset, $self->{local_encode}->encode($name)];
    }
    # }}}2

    return(@fileslist, 0);
} # }}}1

sub releasedir { # {{{1
    my ($self, $dirname, $dh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(dirname = '%s', dh = %d)},
      (caller 3)[3], $dirname || q{}, $dh });

    $self->{callcount}{(caller 0)[3]}++;

    # Not really anything to do; mostly just here to complement opendir().

    return 0;
} # }}}1

sub fsyncdir { # {{{1
    my ($self, $dirname, $flags, $dh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(dirname = '%s', } .
      q{flags = %x, dh = %d)}, (caller 3)[3], $dirname, $flags, $dh });

    $self->{callcount}{(caller 0)[3]}++;

    if (not $flags) {
        my $rc = $self->FPSyncDir($self->{volID}, $dh);
        return -ENOENT() if $rc == $kFPParamErr;
        return -EACCES() if $rc == $kFPAccessDenied;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    return 0;
} # }}}1

sub access { # {{{1
    my ($self, $file, $mode) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', mode = %o)},
      (caller 3)[3], $file, $mode });

    $self->{callcount}{(caller 0)[3]}++;

    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    if ($mode == F_OK) {
        my ($rc, $stat) = $self->lookup_afp_entry($filename);
        return $rc;
    }
    elsif (defined $self->{client_uuid}) {
        my $reqacc = 0;
        if ($mode & R_OK) {
            $reqacc |= $KAUTH_VNODE_GENERIC_READ_BITS;
        }
        if ($mode & W_OK) {
            $reqacc |= $KAUTH_VNODE_GENERIC_WRITE_BITS;
        }
        if ($mode & X_OK) {
            $reqacc |= $KAUTH_VNODE_GENERIC_EXECUTE_BITS;
        }

        my $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $reqacc,
                PathType    => $self->{pathType},
                Pathname    => $filename);
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
        return 0;
    }
    return 0;
} # }}}1

sub create { # {{{1
    my ($self, $file, $mode, $flags) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', mode = %o, } .
      q{flags = %x)}, (caller 3)[3], $file, $mode, $flags });

    $self->{callcount}{(caller 0)[3]}++;

    my $file_n = $file;
    $file = $self->{local_encode}->decode($file);
    my $filename = translate_path($file, $self);

    # afaik this should only ever happen for a plain file...
    return -ENOTSUP() if not S_ISREG($mode);

    my ($rc, $resp) = $self->lookup_afp_entry(path_parent($filename));
    return $rc if $rc;
    if (defined $self->{client_uuid}) {
        $rc = $self->{afpconn}->FPAccess(
                VolumeID    => $self->{volID},
                DirectoryID => $self->{topDirID},
                UUID        => $self->{client_uuid},
                ReqAccess   => $KAUTH_VNODE_ADD_FILE,
                PathType    => $self->{pathType},
                Pathname    => path_parent($filename));
        return -EACCES() if $rc == $kFPAccessDenied;
        return -ENOENT() if $rc == $kFPObjectNotFound;
        return -EBADF()  if $rc != $kFPNoErr;
    }

    $rc = $self->{afpconn}->FPCreateFile(
            VolumeID    => $self->{volID},
            DirectoryID => $resp->{NodeID},
            PathType    => $self->{pathType},
            Pathname    => node_name($filename));
    return -EACCES() if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EBUSY()  if $rc == $kFPFileBusy;
    return -EEXIST() if $rc == $kFPObjectExists;
    return -ENOENT() if $rc == $kFPObjectNotFound;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;

    my $fh;
    ($rc, $fh) = $self->open($file_n, $flags);

    return $rc if $rc;

    # We're ignoring this call's return value intentionally; on an AirPort
    # Disk device, UNIX modes are provided, but you can't change them, so
    # if this fails, it's acceptable.
    $self->chmod($file_n, S_IMODE($mode));
    #return $rc if $rc;

    return($rc, $fh);
} # }}}1

sub ftruncate { # {{{1
    my ($self, $file, $length, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', } .
      q{length = %d, fh = %d)}, (caller 3)[3], $file || q{}, $length,
      ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return -EBADF() if ref $fh;

    my $rc = $self->{afpconn}->FPSetForkParms($fh,
            $self->{DForkLenFlag}, $length);

    return -EPERM()  if $rc == $kFPAccessDenied;
    return -ENOSPC() if $rc == $kFPDiskFull;
    return -EPERM()  if $rc == $kFPLockErr;
    return -EINVAL() if $rc == $kFPParamErr;
    return -EROFS()  if $rc == $kFPVolLocked;
    return -EBADF()  if $rc != $kFPNoErr;
    return 0;
} # }}}1

sub fgetattr { # {{{1
    my ($self, $file, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', fh = %d)},
      (caller 3)[3], $file || q{}, ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    $self->{afpconn}->FPGetUserInfo(0x1, 0, 0x3, \my $selfinfo);
    my $uidmap = $self->{uidmap};
    my $gidmap = $self->{gidmap};
    if (ref $fh) {
        my $timest = time;
        my @stat = (
            # device number (just make it 0, since it's not a real device)
            0,
            # inode number (node ID works fine)
            0,
            # permission mask
            S_ISREG | S_IRUSR | S_IRGRP | S_IROTH,
            # link count
            1,
            # UID number
            exists ${$uidmap}{$selfinfo->{UserID}} ? ${$uidmap}{$selfinfo->{UserID}} : $selfinfo->{UserID},
            # GID number
            exists ${$gidmap}{$selfinfo->{PrimaryGroupID}} ? ${$gidmap}{$selfinfo->{PrimaryGroupID}} : $selfinfo->{PrimaryGroupID},
            # device special major/minor number
            0,
            # file size in bytes
            length(${$fh}),
            # last accessed time
            $timest,
            # data modified time
            $timest,
            # inode changed time
            $timest,
            # preferred block size
            $IO_BLKSIZE,
            # size in blocks
            int((length(${$fh}) + 4095) / 4096),
        ); # }}}2
        return(@stat)
    }

    # Get the filename and parent dir ID from the server, so we can turn
    # around and make an FPGetFileDirParms() call for it. Unfortunately
    # most of the info we want can't be got from FPGetForkParms(), so this
    # is how it has to be done.
    my $bitmap = $kFPParentDirIDBit | $self->{pathFlag};
    my $resp;
    my $rc = $self->{afpconn}->FPGetForkParms($fh, $bitmap, \$resp);

    return -EBADF() if $rc != $kFPNoErr;

    # Was going to go ahead and add support for directories, but with an
    # open filehandle, that really makes no sense here at all.
    $bitmap = $kFPModDateBit | $kFPNodeIDBit | $kFPParentDirIDBit |
            $self->{DForkLenFlag};
    if ($self->{volAttrs} & $kSupportsUnixPrivs) {
        $bitmap |= $kFPUnixPrivsBit;
    }

    my $sresp;
    ($rc, $sresp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID    => $self->{volID},
            DirectoryID => $resp->{ParentDirID},
            PathType    => $self->{pathType},
            Pathname    => $resp->{$self->{pathkey}},
            FileBitmap  => $bitmap);

    return -EBADF() if $rc != $kFPNoErr;

    # assemble stat record {{{2
    my $uid = exists($sresp->{UnixUID}) ? $sresp->{UnixUID} : 0;
    if (exists $self->{uidmap}->{$uid}) {
        $uid = $self->{uidmap}->{$uid};
    }

    my $gid = exists($sresp->{UnixGID}) ? $sresp->{UnixGID} : 0;
    if (exists $self->{gidmap}->{$gid}) {
        $gid = $self->{gidmap}->{$gid};
    }

    my @stat = (
        # device number (just make it 0, since it's not a real device)
        0,
        # inode number (node ID works fine)
        $sresp->{NodeID},
        # permission mask
        exists($sresp->{UnixPerms}) ? $sresp->{UnixPerms} :
                (S_IFREG | S_IRUSR | S_IRGRP | S_IROTH),
        # link count
        1,
        # UID number
        $uid,
        # GID number
        $gid,
        # device special major/minor number
        0,
        # file size in bytes
        $sresp->{$self->{DForkLenKey}},
        # last accessed time
        $sresp->{ModDate} + $self->{timedelta},
        # data modified time
        $sresp->{ModDate} + $self->{timedelta},
        # inode changed time
        $sresp->{ModDate} + $self->{timedelta},
        # preferred block size
        $IO_BLKSIZE,
        # size in blocks
        int(($sresp->{$self->{DForkLenKey}} - 1) / 512) + 1,
    ); # }}}2
    return(@stat)
} # }}}1

##no critic qw(ProhibitBuiltInHomonyms)
sub lock { # {{{1
    my ($self, $file, $cmd, $lkparms, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', cmd = %s, } .
            q{lkparms = %s, fh = %d)}, (caller 3)[3], $file || q{}, $cmd,
            Dumper($lkparms), ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOTSUP() if ref $fh;

    my($rc, $rstart);
    if ($lkparms->{l_whence} == SEEK_CUR) {
        # I doubt this will ever happen, but gotta be sure...
        $self->{logger}->debug('l_whence was SEEK_CUR, we have no way of ' .
                'knowing its current offset?');
        return -EBADF();
    }

    if ($cmd == F_SETLK || $cmd == F_SETLKW) {
        my $flags = 0;
        if ($lkparms->{l_type} == F_UNLCK) {
            $flags |= $kFPLockUnlockFlag;
        }
        if ($lkparms->{l_whence} == SEEK_END) {
            $flags |= $kFPStartEndFlag;
        }
        ($rc, $rstart) = $self->{LockFn}($self->{afpconn},
            Flags       => $flags,
            OForkRefNum => $fh,
            Offset      => $lkparms->{l_start},
            Length      => $lkparms->{l_len} || -1,
        );
        return -ENOLCK() if $rc == $kFPNoMoreLocks;
        return -EACCES() if $rc == $kFPLockErr;
        return -EACCES() if $rc == $kFPRangeOverlap;
        return -EAGAIN() if $rc == $kFPRangeNotLocked;
        return -EBADF()  if $rc != $kFPNoErr;
        return 0;
    }
    elsif ($cmd == F_GETLK) {
        my $flags = 0;
        if ($lkparms->{l_whence} == SEEK_END) {
            $flags |= $kFPStartEndFlag;
        }
        # Since AFP doesn't have a concept of "hey, man, I just want to know
        # if I *could* get a lock", we'll just lock it and then unlock it
        # right away...
        ($rc, $rstart) = $self->{LockFn}(
                                $self,
                                Flags       => $flags,
                                OForkRefNum => $fh,
                                Offset      => $lkparms->{l_start},
                                Length      => $lkparms->{l_len},
                              );
        if ($rc == $kFPLockErr || $rc == $kFPRangeOverlap ||
                $rc == $kFPRangeNotLocked) {
            # Couldn't actually set the lock. FPByteRangeLock{,Ext} doesn't
            # tell us what the specific range of the conflicting lock is, so
            # we just won't change it (thus assuming it's the whole range).
            # We don't actually know the PID either, but since it's not on
            # this system anyway, it wouldn't really matter, so we'll just
            # lie and say it's us holding it.
            $lkparms->{l_pid} = $PROCESS_ID;
            return 0;
        }
        return -ENOLCK() if $rc == $kFPNoMoreLocks;
        return -EBADF()  if $rc != $kFPNoErr;

        # Unlock the speculative lock.
        ($rc, $rstart) = $self->{LockFn}(
                                $self,
                                Flags       => $kFPLockUnlockFlag | $flags,
                                OForkRefNum => $fh,
                                Offset      => $lkparms->{l_start},
                                Length      => $lkparms->{l_len},
                              );

        $lkparms->{l_type} = F_UNLCK;
        return 0;
    }
} # }}}1

sub utimens { # {{{1
    my ($self, $file, $actime, $modtime) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', } .
      q{actime = %s, modtime = %s)}, (caller 3)[3], $file,
      ref $actime ? sprintf('[%d, %d]', @{$actime}) : sprintf('%f', $actime),
      ref $modtime ? sprintf('[%d, %d]', @{$modtime}) : sprintf '%f', $modtime });

    $self->{callcount}{(caller 0)[3]}++;

    # Mostly to test that things work. AFP doesn't really support sub-second
    # time resolution anyway.
    return $self->utime($file, ref $actime ? ${$actime}[0] : $actime,
        ref $modtime ? ${$modtime}[0] : $modtime);
} # }}}1

sub bmap { # {{{1
    my ($self, $file, $blksz, $blkno) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', } .
      q{blksz = %d, blkno = %d)}, (caller 3)[3], $file, $blksz, $blkno });

    $self->{callcount}{(caller 0)[3]}++;

    # This is not a local filesystem that lives on a block device, so bmap()
    # is nonsensical.
    return -ENOTBLK();
} # }}}1

##no critic qw(ProhibitManyArgs ProhibitBuiltInHomonyms)
sub ioctl {
    my ($self, $file, $cmd, $flags, $data, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', cmd = %d, } .
      q{flags = %x, data = %s, fh = %d)}, (caller 3)[3], $file || q{}, $cmd,
      $flags, printable($data), ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOSYS();
}

sub poll {
    my ($self, $file, $ph, $revents, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', ph = %d, } .
      q{revents = %d, fh = %d)}, (caller 3)[3], $file || q{}, $ph, $revents,
      ref($fh) ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOSYS();
}

sub write_buf {
    my ($self, $file, $off, $bufvec, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', off = %d,} .
      q{ bufvec = [...], fh = %d)}, (caller 3)[3], $file || q{}, $off, $fh });

    $self->{callcount}{(caller 0)[3]}++;
    my $filename = translate_path($file, $self);

    return -EBADF() if ref $fh;

    # FIXME: At some point I'd like to alter the AFP library to let me pass
    # multiple strings and/or FD numbers + lengths, and be able to splice()
    # the FD content directly to the AFP sending socket; I don't think now
    # is the best time for that though.

    if ($#{$bufvec} > 0 || $bufvec->[0]{flags} & Fuse::FUSE_BUF_IS_FD()) {
        # Multiple buffers and/or FD source buffers; copy into one big buffer
        # and hand off.
        my $single = [ {
                flags   => 0,
                fd      => -1,
                mem     => undef,
                pos     => 0,
                size    => Fuse::fuse_buf_size($bufvec),
        } ];
        Fuse::fuse_buf_copy($single, $bufvec);
        $bufvec = $single;
    }
    my $ts_start = gettimeofday();
    my($rc, $lastwritten);
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, $lastwritten) = &{$self->{WriteFn}}($self->{afpconn},
                OForkRefNum => $fh,
                Offset      => $off,
                ReqCount    => length($bufvec->[0]{mem}),
                ForkData    => \$bufvec->[0]{mem});
    }
    my $wr_time = gettimeofday() - $ts_start;

    $self->{metrics}->{wr_totaltime} += $wr_time;
    $self->{metrics}->{wr_count}++;
    if ($wr_time > $self->{metrics}->{wr_maxtime}) {
        $self->{metrics}->{wr_maxtime} = $wr_time;
    }
    if ($wr_time < $self->{metrics}->{wr_mintime}) {
        $self->{metrics}->{wr_mintime} = $wr_time;
    }

    my $wr_size = $lastwritten - $off;
    $self->{metrics}->{wr_totalsz} += $wr_size;
    if ($wr_size > $self->{metrics}->{wr_maxsize}) {
        $self->{metrics}->{wr_maxsize} = $wr_size;
    }
    if ($wr_size < $self->{metrics}->{wr_minsize}) {
        $self->{metrics}->{wr_minsize} = $wr_size;
    }

    delete $self->{_getattr_cache}->{$filename};
    return $wr_size;
}

##no critic qw(ProhibitManyArgs)
sub read_buf {
    my ($self, $file, $len, $off, $bufvec, $fh) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', len = %d, } .
      q{off = %d, bufvec = [...], fh = %d)}, (caller 3)[3], $file || q{}, $len,
      $off, ref $fh ? -1 : $fh });

    $self->{callcount}{(caller 0)[3]}++;

    if (ref $fh) {
        # this is gonna be the /._metrics file...
        if ($off > length ${$fh}) {
            return 0;
        }
        if ($off + $len > length ${$fh}) {
            $len = length(${$fh}) - $off;
        }
        $bufvec->[0]{mem} = substr ${$fh}, $off, $len;
        $bufvec->[0]{size} = length $bufvec->[0]{mem};
        return $bufvec->[0]{size};
    }

    my $rc;
    {
        ##no critic qw(ProhibitNoStrict)
        no strict qw(refs);
        ($rc, my $dref) = &{$self->{ReadFn}}($self->{afpconn},
                OForkRefNum => $fh,
                Offset      => $off,
                ReqCount    => $len);
        \$bufvec->[0]{mem} = $dref;
    }
    $bufvec->[0]{size} = length $bufvec->[0]{mem};
    return $bufvec->[0]{size} if $rc == $kFPNoErr or $rc == $kFPEOFErr;
    return -EBADF()   if $rc == $kFPAccessDenied;
    return -ETXTBSY() if $rc == $kFPLockErr;
    return -EINVAL()  if $rc == $kFPParamErr;
    return -EBADF();
}

##no critic qw(ProhibitBuiltInHomonyms)
sub flock {
    my ($self, $file, $fh, $owner, $op) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', fh = %d, } .
      q{owner = %d, op = %x)}, (caller 3)[3], $file || q{}, $fh, $owner, $op });

    $self->{callcount}{(caller 0)[3]}++;

    return -ENOTSUP() if ref $fh;

    if ($op & LOCK_SH) {
        # create a shared lock
        return -ENOTSUP();
    }
    elsif ($op & LOCK_EX) {
        # create an exclusive lock
        my($rc, $rstart) = $self->{LockFn}($self->{afpconn},
            Flags       => 0,
            OForkRefNum => $fh,
            Offset      => 0,
            Length      => -1,
        );
        return -ENOLCK() if $rc == $kFPNoMoreLocks;
        return -EBADF()  if $rc != $kFPNoErr;
    }
    elsif ($op & LOCK_UN) {
        # release existing lock
        my($rc, $rstart) = $self->{LockFn}($self->{afpconn},
            Flags       => $kFPLockUnlockFlag,
            OForkRefNum => $fh,
            Offset      => 0,
            Length      => -1,
        );
        return -ENOLCK() if $rc == $kFPRangeNotLocked;
        return -EBADF()  if $rc != $kFPNoErr;
    }
    return -EINVAL();
}

##no critic qw(ProhibitManyArgs)
sub fallocate {
    my ($self, $file, $fh, $mode, $off, $len) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(file = '%s', fh = %d, } .
      q{mode = %x, off = %d, len = %d)}, (caller 3)[3], $file || q{}, $fh,
      $mode, $off, $len });

    $self->{callcount}{(caller 0)[3]}++;

    # AFP doesn't have any notion of this.
    return -ENOTSUP();
}

# misc. helper functions below:

sub generate_metrics_data { # {{{1
    my ($self) = @_;

    my $data = __PACKAGE__ . " collected client statistics\n\n";

    $data .= 'FUSE API version ' . Fuse::fuse_version() . "\n";
    #$data .= 'FUSE API version ' . join('.', Fuse::fuse_version()) . "\n";
    $data .= 'Net::AFP version ' . $Net::AFP::VERSION . "\n";
    $data .= "Calls made:\n\n";

    my $callcount = $self->{callcount};
    foreach my $key (sort {$a cmp $b} keys %{$callcount}) {
        $data .= (split m{::}sm, $key)[-1] . ":\t" . $callcount->{$key} .
                "\n";
    }

    $data .= "\n";

    $data .= "Average write size:\t";
    if ($self->{metrics}->{wr_count}) {
        $data .= int($self->{metrics}->{wr_totalsz} /
                $self->{metrics}->{wr_count});
    }
    else {
        $data .= '0';
    }
    $data .= " bytes\n";
    $data .= "Largest write size:\t" . $self->{metrics}->{wr_maxsize} .
            " bytes\n";
    $data .= "Smallest write size:\t" . $self->{metrics}->{wr_minsize} .
            " bytes\n";
    $data .= sprintf "Average write time:\t\%.3f seconds\n",
            $self->{metrics}->{wr_count} ?
                ($self->{metrics}->{wr_totaltime} /
                 $self->{metrics}->{wr_count}) : 0;
    $data .= sprintf "Longest write time:\t\%.3f seconds\n",
            $self->{metrics}->{wr_maxtime};
    $data .= sprintf "Shortest write time:\t\%.3f seconds\n",
            $self->{metrics}->{wr_mintime};

    return $data;
} # }}}1

sub lookup_afp_entry { # {{{1
    my ($self, $filename) = @_;

    $self->{logger}->debug(sub { sprintf q{called %s(filename = '%s')},
      (caller 3)[3], printable($filename) });

    # Disabling this for now, as it causes errors with dangling, but
    # otherwise well-formed, symlinks.
#    if (defined $self->{client_uuid}) {
#        my $rc = $self->{afpconn}->FPAccess(
#                VolumeID    => $self->{volID},
#                DirectoryID => $self->{topDirID},
#                UUID        => $self->{client_uuid},
#                ReqAccess   => $KAUTH_VNODE_READ_ATTRIBUTES,
#                PathType    => $self->{pathType},
#                Pathname    => $filename);
#        return -EACCES() if $rc == $kFPAccessDenied;
#        return -ENOENT() if $rc == $kFPObjectNotFound;
#        return -EBADF()  if $rc != $kFPNoErr;
#    }

    #my $filebitmap = $kFPCreateDateBit | $kFPModDateBit | $kFPNodeIDBit |
    my $filebitmap = $kFPModDateBit | $kFPNodeIDBit |
                     $kFPParentDirIDBit | $self->{DForkLenFlag};
    #my $dirbitmap = $kFPCreateDateBit | $kFPModDateBit | $kFPNodeIDBit |
    my $dirbitmap = $kFPModDateBit | $kFPNodeIDBit |
                    $kFPOffspringCountBit | $kFPParentDirIDBit;
    if ($self->{volAttrs} & $kSupportsUnixPrivs) {
        $filebitmap |= $kFPUnixPrivsBit;
        $dirbitmap |= $kFPUnixPrivsBit;
    }

    my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID        => $self->{volID},
            DirectoryID     => $self->{topDirID},
            FileBitmap      => $filebitmap,
            DirectoryBitmap => $dirbitmap,
            PathType        => $self->{pathType},
            Pathname        => $filename);

    return($rc, $resp)   if $rc == $kFPNoErr;
    return -EACCES()     if $rc == $kFPAccessDenied;
    return -ENOENT()     if $rc == $kFPObjectNotFound;
    return -EINVAL()     if $rc == $kFPParamErr;
    return -EBADF();
} # }}}1

sub translate_path { # {{{1
    my ($path, $sessobj) = @_;
    $sessobj->{logger}->debug(sub { sprintf q{called %s(path = '%s')},
      (caller 3)[3], $path });

    my @pathparts = split m{/}sm, $path;
    my @afp_path = ();
    foreach my $elem (@pathparts) {
        next if $elem eq q{.};
        next if $elem eq q{};
        if ($elem eq q{..}) {
            next if scalar(@afp_path) <= 0;
            pop @afp_path;
            next;
        }
        $elem =~ tr{:}{/};
        if ($sessobj->{dotdothack}) { $elem =~ s{^[.][.](.)}{.!..$1}sm; }
        push @afp_path, $elem;
    }
    return join qq{\0}, @afp_path;
} # }}}1

sub node_name { # {{{1
    my ($xlatedpath) = @_;

    my @path_parts = split m{\0}sm, $xlatedpath;
    return pop @path_parts;
} # }}}1

sub path_parent { # {{{1
    my ($xlatedpath) = @_;

    my @path_parts = split m{\0}sm, $xlatedpath;
    pop @path_parts;
    return join qq{\0}, @path_parts;
} # }}}1

# Helper function to convert a byte-string form ACL from the ACL update
# client into the structured form to be sent to the server.
sub acl_from_xattr { # {{{1
    my ($self, $raw_xattr, $acl_data) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(raw_xattr = '%s', } .
      q{acl_data = %s)}, (caller 3)[3], printable($raw_xattr), Dumper($acl_data) });

    # unpack the ACL from the client, so we can structure it to be handed
    # up to the AFP server
    my($acl_flags, @acl_parts) = unpack 'LS/(LS/aLL)', $raw_xattr;
    my(@entries, $bitmap, $utf8name);
    my $entry = {};
    while (($bitmap, $utf8name, @{$entry}{qw(ace_flags ace_rights)}) =
          splice @acl_parts, 0, 4) {
        $utf8name = decode_utf8($utf8name);
        my($uuid, $rc);
        # do the appropriate type of name lookup based on the attributes
        # given in the bitmap field.
        $rc = $kFPNoErr; # <- in case we happen to get it from a local
                         # mapping first...
        if ($bitmap == $kFileSec_UUID) {
            if (exists $self->{u_uuidmap}->{$utf8name}) {
                $uuid = $self->{u_uuidmap}->{$utf8name};
            }
            else {
                $rc = $self->{afpconn}->FPMapName($kUTF8NameToUserUUID,
                        $utf8name, \$uuid);
            }
        }
        elsif ($bitmap == $kFileSec_GRPUUID) {
            if (exists $self->{g_uuidmap}->{$utf8name}) {
                $uuid = $self->{g_uuidmap}->{$utf8name};
            }
            else {
                $rc = $self->{afpconn}->FPMapName($kUTF8NameToGroupUUID,
                        $utf8name, \$uuid);
            }
        }
        else {
            if (exists $self->{u_uuidmap}->{$utf8name}) {
                $uuid = $self->{u_uuidmap}->{$utf8name};
            }
            else {
                $rc = $self->{afpconn}->FPMapName($kUTF8NameToUserUUID,
                        $utf8name, \$uuid);
                if ($rc == $kFPItemNotFound) {
                    if (exists $self->{g_uuidmap}->{$utf8name}) {
                        $uuid = $self->{g_uuidmap}->{$utf8name};
                    }
                    else {
                        $rc = $self->{afpconn}->FPMapName(
                                $kUTF8NameToGroupUUID, $utf8name, \$uuid);
                    }
                }
            }
        }
        # if we can't map a name to a UUID, then just tell the client
        # that we can't proceed.
        return -EINVAL() if $rc != $kFPNoErr;

        $entry->{ace_applicable}    = $uuid;
        push @entries, $entry;
        $entry = {};
    }
    ${$acl_data} = {
                acl_ace     => [ @entries ],
                acl_flags   => $acl_flags,
              };
    return 0;
} # }}}1

# Helper function to convert an AFP ACL into a format that is consumable
# by afp_acl.pl (the tool for manipulating ACLs on an AFP share).
sub acl_to_xattr { # {{{1
    my ($self, $acldata) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(acldata = %s)},
      (caller 3)[3], Dumper($acldata) });

    my @acl_parts;
    foreach my $entry (@{$acldata->{acl_ace}}) {
        my $name;
        # map the UUID (this actually works for both user and group
        # UUIDs, the FPMapID docs are useless) to a corresponding
        # user or group name.
        if (exists $self->{u_uuidmap_r}->{$entry->{ace_applicable}}) {
            $name = $self->{u_uuidmap_r}->{$entry->{ace_applicable}};
        }
        elsif (exists $self->{g_uuidmap_r}->{$entry->{ace_applicable}}) {
            $name = $self->{g_uuidmap_r}->{$entry->{ace_applicable}};
        }
        else {
            my $rc = $self->{afpconn}->FPMapID($kUserUUIDToUTF8Name,
                    $entry->{ace_applicable}, \$name);
            return -EBADF() if $rc != $kFPNoErr;
        }
        push @acl_parts, pack 'LS/aLL', $name->{Bitmap},
                encode_utf8($name->{UTF8Name}),
                @{$entry}{qw[ace_flags ace_rights]};
    }
    # Pack the ACL into a single byte sequence, and push it to the client.
    return pack 'LS/(a*)', $acldata->{acl_flags}, @acl_parts;
} # }}}1

# for nfs4_ace.who
Readonly my $NFS4_ACL_WHO_OWNER_STRING              => q{OWNER@};
Readonly my $NFS4_ACL_WHO_GROUP_STRING              => q{GROUP@};
Readonly my $NFS4_ACL_WHO_EVERYONE_STRING           => q{EVERYONE@};

# for nfs4_ace.type
Readonly my $NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE       => 0;
Readonly my $NFS4_ACE_ACCESS_DENIED_ACE_TYPE        => 1;
Readonly my $NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE         => 2;
Readonly my $NFS4_ACE_SYSTEM_ALARM_ACE_TYPE         => 3;

# for nfs4_ace.whotype
Readonly my $NFS4_ACL_WHO_NAMED                     => 0;
Readonly my $NFS4_ACL_WHO_OWNER                     => 1;
Readonly my $NFS4_ACL_WHO_GROUP                     => 2;
Readonly my $NFS4_ACL_WHO_EVERYONE                  => 3;

# for nfs4_ace.flag
Readonly my $NFS4_ACE_FILE_INHERIT_ACE              => 1<<0;
Readonly my $NFS4_ACE_DIRECTORY_INHERIT_ACE         => 1<<1;
Readonly my $NFS4_ACE_NO_PROPAGATE_INHERIT_ACE      => 1<<2;
Readonly my $NFS4_ACE_INHERIT_ONLY_ACE              => 1<<3;
Readonly my $NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG    => 1<<4;
Readonly my $NFS4_ACE_FAILED_ACCESS_ACE_FLAG        => 1<<5;
Readonly my $NFS4_ACE_IDENTIFIER_GROUP              => 1<<6;
Readonly my $NFS4_ACE_INHERITED_ACE                 => 1<<7;

# for nfs4_ace.access_mask
Readonly my $NFS4_ACE_READ_DATA                     => 1<<0;
Readonly my $NFS4_ACE_LIST_DIRECTORY                => 1<<0;
Readonly my $NFS4_ACE_WRITE_DATA                    => 1<<1;
Readonly my $NFS4_ACE_ADD_FILE                      => 1<<1;
Readonly my $NFS4_ACE_APPEND_DATA                   => 1<<2;
Readonly my $NFS4_ACE_ADD_SUBDIRECTORY              => 1<<2;
Readonly my $NFS4_ACE_READ_NAMED_ATTRS              => 1<<3;
Readonly my $NFS4_ACE_WRITE_NAMED_ATTRS             => 1<<4;
Readonly my $NFS4_ACE_EXECUTE                       => 1<<5;
Readonly my $NFS4_ACE_DELETE_CHILD                  => 1<<6;
Readonly my $NFS4_ACE_READ_ATTRIBUTES               => 1<<7;
Readonly my $NFS4_ACE_WRITE_ATTRIBUTES              => 1<<8;
Readonly my $NFS4_ACE_WRITE_RETENTION               => 1<<9;
Readonly my $NFS4_ACE_WRITE_RETENTION_HOLD          => 1<<10;
Readonly my $NFS4_ACE_DELETE                        => 1<<16;
Readonly my $NFS4_ACE_READ_ACL                      => 1<<17;
Readonly my $NFS4_ACE_WRITE_ACL                     => 1<<18;
Readonly my $NFS4_ACE_WRITE_OWNER                   => 1<<19;
Readonly my $NFS4_ACE_SYNCHRONIZE                   => 1<<20;
Readonly my $NFS4_ACE_GENERIC_READ                  => 0x00120081;
Readonly my $NFS4_ACE_GENERIC_WRITE                 => 0x00160106;
Readonly my $NFS4_ACE_GENERIC_EXECUTE               => 0x001200A0;
Readonly my $NFS4_ACE_MASK_ALL                      => 0x001F01FF;

my %afp_to_nfs4_access_bits = (
    $KAUTH_VNODE_READ_DATA              => $NFS4_ACE_READ_DATA,
    $KAUTH_VNODE_WRITE_DATA             => $NFS4_ACE_WRITE_DATA,
    $KAUTH_VNODE_EXECUTE                => $NFS4_ACE_EXECUTE,
    $KAUTH_VNODE_DELETE                 => $NFS4_ACE_DELETE,
    $KAUTH_VNODE_APPEND_DATA            => $NFS4_ACE_APPEND_DATA,
    $KAUTH_VNODE_DELETE_CHILD           => $NFS4_ACE_DELETE_CHILD,
    $KAUTH_VNODE_READ_ATTRIBUTES        => $NFS4_ACE_READ_ATTRIBUTES,
    $KAUTH_VNODE_WRITE_ATTRIBUTES       => $NFS4_ACE_WRITE_ATTRIBUTES,
    $KAUTH_VNODE_READ_EXTATTRIBUTES     => $NFS4_ACE_READ_NAMED_ATTRS,
    $KAUTH_VNODE_WRITE_EXTATTRIBUTES    => $NFS4_ACE_WRITE_NAMED_ATTRS,
    $KAUTH_VNODE_READ_SECURITY          => $NFS4_ACE_READ_ACL,
    $KAUTH_VNODE_WRITE_SECURITY         => $NFS4_ACE_WRITE_ACL,
    $KAUTH_VNODE_TAKE_OWNERSHIP         => $NFS4_ACE_WRITE_OWNER,
    $KAUTH_VNODE_SYNCHRONIZE            => $NFS4_ACE_SYNCHRONIZE,
);

my %afp_ace_flags_to_nfs4_flag_bits = (
    $KAUTH_ACE_FILE_INHERIT         => $NFS4_ACE_FILE_INHERIT_ACE,
    $KAUTH_ACE_DIRECTORY_INHERIT    => $NFS4_ACE_DIRECTORY_INHERIT_ACE,
    $KAUTH_ACE_LIMIT_INHERIT        => $NFS4_ACE_NO_PROPAGATE_INHERIT_ACE,
    $KAUTH_ACE_ONLY_INHERIT         => $NFS4_ACE_INHERIT_ONLY_ACE,
    $KAUTH_ACE_SUCCESS              => $NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG,
    $KAUTH_ACE_FAILURE              => $NFS4_ACE_FAILED_ACCESS_ACE_FLAG,
    $KAUTH_ACE_INHERITED            => $NFS4_ACE_INHERITED_ACE,
);

my %afp_ace_type_to_nfs4_type_values = (
    $KAUTH_ACE_PERMIT   => $NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
    $KAUTH_ACE_DENY     => $NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
    $KAUTH_ACE_AUDIT    => $NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE,
    $KAUTH_ACE_ALARM    => $NFS4_ACE_SYSTEM_ALARM_ACE_TYPE,
);

my %nfs4_type_to_afp_ace_type_values = ();
for my $key (keys %afp_ace_type_to_nfs4_type_values) {
    $nfs4_type_to_afp_ace_type_values{$afp_ace_type_to_nfs4_type_values{$key}} = $key;
}

my @nfs4_def_acl_params = (
  {
    who           => $NFS4_ACL_WHO_OWNER_STRING,
    flag          => 0,
    unix_mode     => S_IRWXU,
    access_rights => $kRPOwner | $kWPOwner | $kSPOwner,
    access_flags  => [
      {
        acl_mask      => $NFS4_ACE_GENERIC_READ,
        unix_mode     => S_IRUSR,
        access_rights => $kRPOwner,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_WRITE,
        unix_mode     => S_IWUSR,
        access_rights => $kWPOwner,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_EXECUTE,
        unix_mode     => S_IXUSR,
        access_rights => $kSPOwner,
      },
    ],
  },
  {
    who           => $NFS4_ACL_WHO_GROUP_STRING,
    flag          => $NFS4_ACE_IDENTIFIER_GROUP,
    unix_mode     => S_IRWXG,
    access_rights => $kRPGroup | $kWPGroup | $kSPGroup,
    access_flags  => [
      {
        acl_mask      => $NFS4_ACE_GENERIC_READ,
        unix_mode     => S_IRGRP,
        access_rights => $kRPGroup,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_WRITE,
        unix_mode     => S_IWGRP,
        access_rights => $kWPGroup,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_EXECUTE,
        unix_mode     => S_IXGRP,
        access_rights => $kSPGroup,
      },
    ],
  },
  {
    who           => $NFS4_ACL_WHO_EVERYONE_STRING,
    flag          => 0,
    unix_mode     => S_IRWXO,
    access_rights => $kRPOther | $kWPOther | $kSPOther,
    access_flags  => [
      {
        acl_mask      => $NFS4_ACE_GENERIC_READ,
        unix_mode     => S_IROTH,
        access_rights => $kRPOther,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_WRITE,
        unix_mode     => S_IWOTH,
        access_rights => $kWPOther,
      },
      {
        acl_mask      => $NFS4_ACE_GENERIC_EXECUTE,
        unix_mode     => S_IXOTH,
        access_rights => $kSPOther,
      },
    ],
  },
);

my %nfs4_reserved_who_names;
# instead of having two things with similar stuff, keep one source of truth
for my $item (@nfs4_def_acl_params) {
    $nfs4_reserved_who_names{${$item}{who}} = $item;
}

sub acl_from_nfsv4_xattr { # {{{1
    my ($self, $raw_xattr, $acl_data, $filename) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(raw_xattr = '%s', } .
      q{acl_data = %s)}, (caller 3)[3], printable($raw_xattr), Dumper($acl_data) });

    # unpack the ACL from the client, so we can structure it to be handed
    # up to the AFP server
    my @acl_parts = unpack 'L>/(L>L>L>L>/ax![L])', $raw_xattr;
    my @entries;
    my $unix_mode = 0;
    my $afp_rights = 0;
    while (my ($type, $flag, $access_mask, $who) = splice @acl_parts, 0, 4) {
        $who = decode_utf8($who);
        my $entry = {};
        # access_mask (NFSv4) -> ace_rights (AFP)
        $entry->{ace_rights} = 0;
        for my $key (keys %afp_to_nfs4_access_bits) {
            if (($access_mask & $afp_to_nfs4_access_bits{$key}) ==
              $afp_to_nfs4_access_bits{$key}) {
                $entry->{ace_rights} |= $key;
            }
        }

        # flag, type (NFSv4) -> ace_flags (AFP)
        $entry->{ace_flags} = 0;
        for my $key (keys %afp_ace_flags_to_nfs4_flag_bits) {
            if (($flag & $afp_ace_flags_to_nfs4_flag_bits{$key}) ==
              $afp_ace_flags_to_nfs4_flag_bits{$key}) {
                $entry->{ace_flags} |= $key;
            }
        }
        $entry->{ace_flags} |= $nfs4_type_to_afp_ace_type_values{$type};

        # who, flag (NFSv4) -> ace_applicable (AFP)
        my $uuid;
        # Collect the UNIX perms mode for changing the actual perms later.
        if (exists $nfs4_reserved_who_names{$who}) {
            my $params = $nfs4_reserved_who_names{$who};
            if ($access_mask == $NFS4_ACE_MASK_ALL) {
                $unix_mode  |= $params->{unix_mode};
                $afp_rights |= $params->{access_rights};
                next;
            }

            for my $ent (@{$params->{access_flags}}) {
                if (($access_mask & $ent->{acl_mask}) == $ent->{acl_mask}) {
                    $unix_mode  |= $ent->{unix_mode};
                    $afp_rights |= $ent->{access_rights};
                }
            }
            next;
        }
        my $resp;
        my $rc = $self->{afpconn}->FPGetSrvrInfo(\$resp);
        return -EINVAL if $rc != $kFPNoErr;
        $who =~ s{\@$resp->{UTF8ServerName}$}{}sm;
        if ($flag & $NFS4_ACE_IDENTIFIER_GROUP) {
            if (exists $self->{g_uuidmap}->{$who}) {
                $uuid = $self->{g_uuidmap}->${who};
            }
            else {
                $rc = $self->{afpconn}->FPMapName($kUTF8NameToGroupUUID,
                        $who, \$uuid);
                return -EINVAL if $rc != $kFPNoErr;
            }
        }
        else {
            if (exists $self->{u_uuidmap}->{$who}) {
                $uuid = $self->{u_uuidmap}->${who};
            }
            else {
                $rc = $self->{afpconn}->FPMapName($kUTF8NameToUserUUID,
                        $who, \$uuid);
                return -EINVAL if $rc != $kFPNoErr;
            }
        }
        $entry->{ace_applicable} = $uuid;

        push @entries, $entry;
    }

    # Actually do the UNIX perms update here...
    my($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            FileBitmap  => $kFPUnixPrivsBit,
            PathType    => $self->{pathType},
            Pathname    => $filename);
    return -EBADF() if $rc != $kFPNoErr;

    # We want the type and suid/sgid/sticky bits preserved.
    $unix_mode |= ($resp->{UnixPerms} & ~(S_IRWXU | S_IRWXG | S_IRWXO));

    $rc = $self->{afpconn}->FPSetFileDirParms(
            VolumeID            => $self->{volID},
            DirectoryID         => $self->{topDirID},
            Bitmap              => $kFPUnixPrivsBit,
            PathType            => $self->{pathType},
            Pathname            => $filename,
            UnixPerms           => $unix_mode,
            UnixUID             => $resp->{UnixUID},
            UnixGID             => $resp->{UnixGID},
            UnixAccessRights    => $afp_rights);
    return -EBADF() if $rc != $kFPNoErr;
    delete $self->{_getattr_cache}->{$filename};

    ${$acl_data} = {
                acl_ace     => [ @entries ],
                # dunno what these flags actually do, and 0 seems to be
                # a safe value.
                acl_flags   => 0,
              };
    return 0;
} # }}}1

sub acl_to_nfsv4_xattr { # {{{1
    my ($self, $acldata, $filename) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(acldata = %s)},
            (caller 3)[3], Dumper($acldata) });

    my @acl_parts;
    foreach my $entry (@{$acldata->{acl_ace}}) {
        my ($type, $flag, $access_mask, $who) = (0, 0, 0, q{});
        my $name;
        # ace_applicable (AFP) -> who, whotype (NFSv4)
        if (exists $self->{u_uuidmap_r}->{$entry->{ace_applicable}}) {
            $name = $self->{u_uuidmap_r}->{$entry->{ace_applicable}};
        }
        elsif (exists $self->{g_uuidmap_r}->{$entry->{ace_applicable}}) {
            $name = $self->{g_uuidmap_r}->{$entry->{ace_applicable}};
            $flag |= $NFS4_ACE_IDENTIFIER_GROUP;
        }
        else {
            my $rc = $self->{afpconn}->FPMapID($kUserUUIDToUTF8Name,
                    $entry->{ace_applicable}, \$name);
            return -EBADF() if $rc != $kFPNoErr;
            if ($name->{Bitmap} == 2) {
                $flag |= $NFS4_ACE_IDENTIFIER_GROUP;
            }
        }
        my $resp;
        my $rc = $self->{afpconn}->FPGetSrvrInfo(\$resp);
        $who = $name->{UTF8Name} . q{@} . $resp->{UTF8ServerName};

        # ace_flags (AFP) -> flag, type (NFSv4)
        my $kind = $entry->{ace_flags} & $KAUTH_ACE_KINDMASK;
        $type = $afp_ace_type_to_nfs4_type_values{$kind};
        for my $key (keys %afp_ace_flags_to_nfs4_flag_bits) {
            if (($entry->{ace_flags} & $key) == $key) {
                $flag |= $afp_ace_flags_to_nfs4_flag_bits{$key};
            }
        }

        # ace_rights (AFP) -> access_mask (NFSv4)
        for my $key (keys %afp_to_nfs4_access_bits) {
            # transcribe the access bits appropriately
            if (($entry->{ace_rights} & $key) == $key) {
                $access_mask |= $afp_to_nfs4_access_bits{$key};
            }
        }
        push @acl_parts, $type, $flag, $access_mask,
            encode_utf8($who);
    }

    # get UNIX access rights and form the default owner/group/everyone entries
    my ($rc, $resp) = $self->{afpconn}->FPGetFileDirParms(
            VolumeID    => $self->{volID},
            DirectoryID => $self->{topDirID},
            FileBitmap  => $kFPUnixPrivsBit,
            PathType    => $self->{pathType},
            Pathname    => $filename);

    for my $params (@nfs4_def_acl_params) {
        my $access_mask = 0;
        if (($resp->{UnixPerms} & $params->{unix_mode}) == $params->{unix_mode}) {
            $access_mask |= $NFS4_ACE_MASK_ALL;
        }
        else {
            for my $ent (@{$params->{access_flags}}) {
                if ($resp->{UnixPerms} & $ent->{unix_mode}) {
                    $access_mask |= $ent->{acl_mask}
                }
            }
        }
        push @acl_parts, $NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE, $params->{flag},
            $access_mask, encode_utf8($params->{who});
    }

    return pack 'L>(L>L>L>L>/ax![L])*', scalar(@{$acldata->{acl_ace}}) + 3, @acl_parts;
} # }}}1

1;
# vim: ts=4 fdm=marker sw=4 et
