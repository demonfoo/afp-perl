# $HeadURL$
# $Revision$
# $Date$

# imports {{{1
package Net::AFP;
use strict;
use warnings;
use Net::AFP::Result;
use Net::AFP::VolParms;
use Net::AFP::Parsers;
use Net::AFP::TokenTypes;
use Net::AFP::ACL;
use Net::AFP::ExtAttrs;
use Net::AFP::FileParms qw(:DEFAULT !:common);
use Net::AFP::DirParms;
use Net::AFP::MapParms;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Exporter qw(import);
use Log::Log4perl qw(:easy);
use Carp;
# }}}1

our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
                 kFPHardCreate kFPStartEndFlag kFPLockUnlockFlag);

# define constants {{{1
our $VERSION = '0.61.1';
use constant kFPByteRangeLock           => 1;   # AFP 2.0
use constant kFPCloseVol                => 2;   # AFP 2.0
use constant kFPCloseDir                => 3;   # AFP 2.0
use constant kFPCloseFork               => 4;   # AFP 2.0
use constant kFPCopyFile                => 5;   # AFP 2.0
use constant kFPCreateDir               => 6;   # AFP 2.0
use constant kFPCreateFile              => 7;   # AFP 2.0
use constant kFPDelete                  => 8;   # AFP 2.0
use constant kFPEnumerate               => 9;   # AFP 2.0
use constant kFPFlush                   => 10;  # AFP 2.0
use constant kFPFlushFork               => 11;  # AFP 2.0
use constant kFPGetForkParms            => 14;  # AFP 2.0
use constant kFPGetSrvrInfo             => 15;  # AFP 2.0
use constant kFPGetSrvrParms            => 16;  # AFP 2.0
use constant kFPGetVolParms             => 17;  # AFP 2.0
use constant kFPLogin                   => 18;  # AFP 2.0
use constant kFPLoginCont               => 19;  # AFP 2.0
use constant kFPLogout                  => 20;  # AFP 2.0
use constant kFPMapID                   => 21;  # AFP 2.0
use constant kFPMapName                 => 22;  # AFP 2.0
use constant kFPMoveAndRename           => 23;  # AFP 2.0
use constant kFPOpenVol                 => 24;  # AFP 2.0
use constant kFPOpenDir                 => 25;  # AFP 2.0
use constant kFPOpenFork                => 26;  # AFP 2.0
use constant kFPRead                    => 27;  # AFP 2.0
use constant kFPRename                  => 28;  # AFP 2.0
use constant kFPSetDirParms             => 29;  # AFP 2.0
use constant kFPSetFileParms            => 30;  # AFP 2.0
use constant kFPSetForkParms            => 31;  # AFP 2.0
use constant kFPSetVolParms             => 32;  # AFP 2.0
use constant kFPWrite                   => 33;  # AFP 2.0
use constant kFPGetFileDirParms         => 34;  # AFP 2.0
use constant kFPSetFileDirParms         => 35;  # AFP 2.0
use constant kFPChangePassword          => 36;  # AFP 2.0
use constant kFPGetUserInfo             => 37;  # AFP 2.0
use constant kFPGetSrvrMsg              => 38;  # AFP 2.1
use constant kFPCreateID                => 39;  # AFP 2.1
use constant kFPDeleteID                => 40;  # AFP 2.1
use constant kFPResolveID               => 41;  # AFP 2.1
use constant kFPExchangeFiles           => 42;  # AFP 2.1
use constant kFPCatSearch               => 43;  # AFP 2.1
use constant kFPOpenDT                  => 48;  # AFP 2.0
use constant kFPCloseDT                 => 49;  # AFP 2.0
use constant kFPGetIcon                 => 51;  # AFP 2.0
use constant kFPGetIconInfo             => 52;  # AFP 2.0
use constant kFPAddAPPL                 => 53;  # AFP 2.0
use constant kFPRemoveAPPL              => 54;  # AFP 2.0
use constant kFPGetAPPL                 => 55;  # AFP 2.0
use constant kFPAddComment              => 56;  # AFP 2.0
use constant kFPRemoveComment           => 57;  # AFP 2.0
use constant kFPGetComment              => 58;  # AFP 2.0
use constant kFPByteRangeLockExt        => 59;  # AFP 3.0
use constant kFPReadExt                 => 60;  # AFP 3.0
use constant kFPWriteExt                => 61;  # AFP 3.0
use constant kFPGetAuthMethods          => 62;  # AFP 3.1
use constant kFPLoginExt                => 63;  # AFP 3.1
use constant kFPGetSessionToken         => 64;  # AFP 3.1
use constant kFPDisconnectOldSession    => 65;  # AFP 3.1
use constant kFPEnumerateExt            => 66;
use constant kFPCatSearchExt            => 67;
use constant kFPEnumerateExt2           => 68;
use constant kFPGetExtAttr              => 69;  # AFP 3.2
use constant kFPSetExtAttr              => 70;  # AFP 3.2
use constant kFPRemoveExtAttr           => 71;  # AFP 3.2
use constant kFPListExtAttrs            => 72;  # AFP 3.2
use constant kFPGetACL                  => 73;  # AFP 3.2
use constant kFPSetACL                  => 74;  # AFP 3.2
use constant kFPAccess                  => 75;  # AFP 3.2
use constant kFPSpotlightPrivate        => 76;  # AFP 3.2 (OS X 10.5?)
use constant kFPSyncDir                 => 78;  # AFP 3.2 (OS X 10.5?)
use constant kFPSyncFork                => 79;  # AFP 3.2 (OS X 10.5?)
use constant kFPZzzzz                   => 122; # AFP 2.3
use constant kFPAddIcon                 => 192; # AFP 2.0
# }}}1

=head1 NAME

Net::AFP - Perl module implementing an interface for accessing Apple File Protocol exports

=head1 SYNOPSIS

This package should not be used directly in most cases. It implements only
the methods to support general AFP operations. Low-level details of the
transport/connection setup/etc. are handled by the protocol-specific
packages C<Net::AFP::TCP> and C<Net::AFP::Atalk>. Use them instead.

=head1 DESCRIPTION

This package forms the basis for a Perl class providing an interface to
connect to an AFP server and perform operations on remote files and
directories within an exported share.

This class is not intended for direct use - currently, the
C<Net::AFP::TCP> and C<Net::AFP::Atalk> packages derive this class.
This class implements generalized functionality; protocol-specific
functionality is completely abstracted out from this class.

Note that not all AFP operations are implemented. The documentation describes
a few functions which I have not implemented due to lack of need.

=head2 Path Type Constants

Constants indicating the type of names in a C<$Pathname> parameter.

=over

=item kFPShortName

Indicates that a C<$Pathname> parameter contains Short Names.

=cut
use constant kFPShortName       => 1;
=item kFPLongName

Indicates that a C<$Pathname> parameter contains Long Names.

=cut
use constant kFPLongName        => 2;
=item kFPUTF8Name

Indicates that a C<$Pathname> parameter contains an AFPName, which
consists of a four-byte text encoding hint followed a two-byte length,
followed by a UTF-8 encoded pathname.

=cut
use constant kFPUTF8Name        => 3;

=back

=head2 File Creation Constants

Constants used when creating files. These constants are used in the
C<Flag> parameter for the L</FPCreateFile()> command.

=over

=item kFPSoftCreate

Indicates soft file creation.

=cut
use constant kFPSoftCreate      => 0;
=item kFPHardCreate

Indicates hard file creation.

=cut
use constant kFPHardCreate      => 0x80;


use constant kFPStartEndFlag    => 0x80;
use constant kFPLockUnlockFlag  => 1;
=back

=head2 Catalog Node Names



=head1 SUBROUTINES/METHODS

These are the actual AFP server commands which can be issued to an open
AFP server object.

=over

=cut

# This class is only to be inherited. It uses virtual methods to talk to
# the server by whatever protocol the inheriting class is supposed to
# talk over, so we want this to be as generic as possible.
sub new { # {{{1
    my ($class, $host, $port) = @_;
    DEBUG('called ', (caller(0))[3]);
    my $obj = {};
    bless $obj, $class;
    my $logparms = <<_EOT_;
log4perl.logger = INFO, status
log4perl.appender.status = Log::Dispatch::Syslog
log4perl.appender.status.Facility = user
log4perl.appender.status.layout = PatternLayout
log4perl.appender.status.layout.ConversionPattern = [%P] %F line: %L %c - %m%n

_EOT_

#    if (defined $::__AFP_DEBUG) {
#        $logparms .= <<_EOT_;
#log4perl.logger = DEBUG, stderr
#
#_EOT_
##        push(@logparms, { 'level' => $DEBUG, 'file' => 'STDERR' });
#    }
    Log::Log4perl->init(\$logparms);
    return $obj;
} # }}}1

# This is here so that Perl won't die of an "unknown method" if an
# inheriting class doesn't implement it. It's just a "virtual method"
# placeholder. It really shouldn't be called outside of a method anyway.
# Outside callers should be using the methods implemented for the AFP
# operations.
sub SendAFPMessage { # {{{1
    DEBUG('called ', (caller(0))[3]);
    ERROR('called ', (caller(0))[3], ' at line ', (caller(0))[2], ((caller(0))[1] eq q/-/ ? ' on standard in' : ' in file ' . (caller(0))[1]));
    croak('Do not call the base class SendAFPMessage method');
} # }}}1

sub SendAFPWrite { # {{{1
    DEBUG('called ', (caller(0))[3]);
    ERROR('called ', (caller(0))[3], ' at line ', (caller(0))[2], ((caller(0))[1] eq q/-/ ? ' on standard in' : ' in file ' . (caller(0))[1]));
    croak('Do not call the base class SendAFPWrite method');
} # }}}1

sub PackagePath { # {{{1
    my ($PathType, $Pathname, $NoEncType) = @_;

    $Pathname ||= q//;

    if ($PathType == kFPShortName or $PathType == kFPLongName) {
        return pack('CC/a*', $PathType, encode('MacRoman', $Pathname));
    }
    elsif ($PathType == kFPUTF8Name) {
        my $encodedPath = encode_utf8(decompose($Pathname));
        if ($NoEncType) {
            return pack('Cn/a*', $PathType, $encodedPath);
        }
        else {
            return pack('CNn/a*', $PathType, 0, $encodedPath);
        }
    }
    ERROR("Invalid path type ", $PathType, "; called from '", (caller(1))[1],
            "', line ", (caller(1))[2]);
    croak;
} # }}}1

sub PackSetParams { # {{{1
    my ($Bitmap, %options) = @_;

    my $ParamsBlock = q//;

    if ($Bitmap & kFPAttributeBit) {
        return unless exists $options{'Attribute'};
        $ParamsBlock .= pack('n', $options{'Attribute'});
    }

    if ($Bitmap & kFPCreateDateBit) {
        return unless exists $options{'CreateDate'};
        my $time = $options{'CreateDate'} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPModDateBit) {
        return unless exists $options{'ModDate'};
        my $time = $options{'ModDate'} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPBackupDateBit) {
        return unless exists $options{'BackupDate'};
        my $time = $options{'BackupDate'} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPFinderInfoBit) {
        return unless exists $options{'FinderInfo'};
        $ParamsBlock .= pack('a[32]', $options{'FinderInfo'});
    }

    if ($Bitmap & kFPOwnerIDBit) {
        return unless exists $options{'OwnerID'};
        $ParamsBlock .= pack('N', $options{'OwnerID'});
    }

    if ($Bitmap & kFPGroupIDBit) {
        return unless exists $options{'GroupID'};
        $ParamsBlock .= pack('N', $options{'GroupID'});
    }

    if ($Bitmap & kFPAccessRightsBit) {
        return unless exists $options{'AccessRights'};
        $ParamsBlock .= pack('N', $options{'AccessRights'});
    }

    # kFPLaunchLimitBit? what it do? can has knows?

    if ($Bitmap & kFPUnixPrivsBit) {
        return unless exists $options{'UnixUID'};
        return unless exists $options{'UnixGID'};
        return unless exists $options{'UnixPerms'};
        return unless exists $options{'UnixAccessRights'};

        $ParamsBlock .= pack('NNNN', @options{'UnixUID', 'UnixGID', 'UnixPerms',
                                              'UnixAccessRights'});
    }

    return $ParamsBlock;
} # }}}1

=item FPAccess( [ARGS] )

Requests access to a file or directory on a volume for which ACLs are
enabled.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume identifier; required.

=item DirectoryID

Directory identifier; required.

=item Bitmap

Reserved.

=item UUID

Universally Unique Identifier (UUID) of the process sending this command;
required.

=item ReqAccess

Requested access; required. For definitions, see
L<Net::AFP::ACL/"ACL Access Rights">.

=item PathType

Type of names in C<Pathname>; required. See L</"Path Type Constants"> for possible
values.

=item Pathname

Pathname to the file or directory for which access is being requested;
required.

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to request access to
the file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPAccess { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    croak('UUID must be provided')
            unless exists $options{'UUID'};
    croak('ReqAccess must be provided')
            unless exists $options{'ReqAccess'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNna[16]Na*', kFPAccess,
            @options{'VolumeID', 'DirectoryID', 'Bitmap',},
            uuid_pack($options{'UUID'}), $options{'ReqAccess'},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPAddAPPL( [ARGS] )

Adds an APPL mapping to the Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number; required.

=item DirectoryID

Directory ID; required.

=item FileCreator

File creator of the application corresponding to the APPL mapping being
added; required.

=item ApplTag

User-defined tag stored with the APPL mapping; required.

=item PathType

Type of names in C<Pathname>; required. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory; required.

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to add an APPL mapping.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file.

=item kFPObjectTypeErr

Input parameters point to a directory.

=item kFPParamErr

Session reference or Desktop database reference number is unknown;
pathname is invalid.

=back

=cut
sub FPAddAPPL {
    my($self, %options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('FileCreator must be provided')
            unless exists $options{'FileCreator'};
    croak('ApplTag must be provided')
            unless exists $options{'ApplTag'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNNNa*', kFPAddAPPL,
            @options{'DTRefNum', 'DirectoryID', 'FileCreator', 'ApplTag'},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
}

=item FPAddComment()

Adds a comment for a file or directory to a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number; required.

=item DirectoryID

Directory ID; required.

=item PathType

Type of names in C<Pathname>; required. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory; required.

=item Comment

Comment data to be associated with the specified file or directory;
required.

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPAddComment { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('Comment must be provided')
            unless exists $options{'Comment'};

    my $msg = pack('CxnNa*x![s]C/a', kFPAddComment,
            @options{'DTRefNum', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $options{'Comment'});
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPAddIcon()

Adds an icon bitmap to a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number.

=item FileCreator

File creator associated with the icon that is to be added.

=item FileType

File type associated with the icon that is to be added.

=item IconType

Type of icon that is to be added.

=item IconTag

Tag information to be stored with the icon.

=item BitmapSize

Size of the bitmap for this icon.

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPParamErr

Session reference number or Desktop database reference number is
unknown, or pathname is invalid.

=item kFPIconTypeErr

New icon's size does not match that of the existing icon.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPAddIcon {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('FileCreator must be provided')
            unless exists $options{'FileCreator'};
    croak('FileType must be provided')
            unless exists $options{'FileType'};
    croak('IconType must be provided')
            unless exists $options{'IconType'};
    croak('IconTag must be provided')
            unless exists $options{'IconTag'};
    croak('BitmapSize must be provided')
            unless exists $options{'BitmapSize'};
    croak('IconBitmap must be provided')
            unless exists $options{'IconBitmap'};

    my $msg = pack('CxnNNCxNn', kFPAddIcon,
            @options{'DTRefNum', 'FileCreator', 'FileType', 'IconType',
                     'IconTag', 'BitmapSize'});
    return $self->SendAFPWrite($msg, \$options{'IconBitmap'});
}

=item FPByteRangeLock()

Locks or unlocks a specified range of bytes within an open fork.

Deprecated; use C<FPByteRangeLockExt()> instead.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item Flags

Bit 0 is the C<LockUnlock> bit, where 0 indicates lock and 1 indicates
unlock. Bit 7 is the C<StartEndFlag> bit, where 0 indicates that
C<Offset> is relative to the beginning of the fork and 1 indicates
that C<Offset> is relative to the end of the fork. The C<StartEndFlag>
bit is only used when locking a range.

=item OForkRefNum

Open fork reference number.

=item Offset

Offset to the first byte of the range to be locked or unlocked (can
be negative if the C<StartEndFlag> bit is set to 1).

=item Length

Number of bytes to be locked or unlocked (a signed, positive long
integer; cannot be negative except for the special value -1).

=back

Returns:

A scalar indicating the error code from the call, and upon success, an
additional scalar corresponding to the byte offset of the start of the
locked range.

Error replies:

=over

=item kFPLockErr

Some or all of the requested range is locked by another user.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPNoMoreLocks

Server's maximum lock count has been reached.

=item kFPParamErr

Session reference number or open fork reference number is unknown; a
combination of the C<StartEndFlag> bit and C<Offset> specifies a range
that starts before byte zero.

=item kFPRangeNotLocked

User tried to unlock a range that is locked by another user or that
is not locked at all.

=item kFPRangeOverlap

User tried to lock some or all of a range that the user has already
locked.

=back

=cut
sub FPByteRangeLock { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flags'} ||= 0;
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('Length must be provided')
            unless exists $options{'Length'};

    my $msg = pack('CCnNN', kFPByteRangeLock,
            @options{'Flags', 'OForkRefNum'},
            long_convert($options{'Offset'}),
            long_convert($options{'Length'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') unless wantarray();
        return($rc, unpack('N', $resp));
    }
    return $rc;
} # }}}1

=item FPByteRangeLockExt()

Locks or unlocks a specified range of bytes within an open fork.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item Flags

Bit 0 is the C<LockUnlock> bit, where 0 indicates lock and 1 indicates
unlock. Bit 7 is the C<StartEndFlag> bit, where 0 indicates that
C<Offset> is relative to the beginning of the fork and 1 indicates
that C<Offset> is relative to the end of the fork. The C<StartEndFlag>
bit is only used when locking a range.

=item OForkRefNum

Open fork reference number.

=item Offset

Offset to the first byte of the range to be locked or unlocked (can
be negative if the C<StartEndFlag> bit is set to 1).

=item Length

Number of bytes to be locked or unlocked (a signed, positive long
integer; cannot be negative except for the special value -1).

=back

Returns:

A scalar indicating the error code from the call, and upon success, an
additional scalar corresponding to the byte offset of the start of the
locked range.

Error replies:

=over

=item kFPLockErr

Some or all of the requested range is locked by another user.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPNoMoreLocks

Server's maximum lock count has been reached.

=item kFPParamErr

Session reference number or open fork reference number is unknown; a
combination of the C<StartEndFlag> bit and C<Offset> specifies a range
that starts before byte zero.

=item kFPRangeNotLocked

User tried to unlock a range that is locked by another user or that
is not locked at all.

=item kFPRangeOverlap

User tried to lock some or all of a range that the user has already
locked.

=back

=cut
sub FPByteRangeLockExt { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flags'} ||= 0;
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('Length must be provided')
            unless exists $options{'Length'};

    my $msg = pack('CCnNNNN', kFPByteRangeLock,
            @options{'Flags', 'OForkRefNum'},
            ll_convert($options{'Offset'}),
            ll_convert($options{'Length'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') unless wantarray();
        return($rc, ll_unconvert(unpack('NN', $resp)));
    }
    return $rc;
} # }}}1

=item FPCatSearch()

Searches a volume for files and directories that match specified criteria.

Deprecated; use C<FPCatSearchExt()> instead.

Not yet implemented.

=cut
sub FPCatSearch {
    DEBUG('called ', (caller(0))[3]);
    ERROR('called function ', (caller(0))[3], ' not implemented');
    croak('Not yet implemented');
}

=item FPCatSearchExt()

Searches a volume for files and directories that match specified criteria.

Not yet implemented.

=cut
sub FPCatSearchExt {
    DEBUG('called ', (caller(0))[3]);
    ERROR('called function ', (caller(0))[3], ' not implemented');
    croak('Not yet implemented');
}

=item FPChangePassword()

Allow users to change their passwords.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $UAM

String specifying the UAM to use.

=item $UserName

Name of the user whose password is to be changed. Starting with AFP 3.0,
C<$UserName> is two bytes with each byte set to zero. The first byte
indicates a zero length string, and the second byte is a pad byte.

Please pass C<undef> or an empty string.

=item $UserAuthInfo

UAM-specific information.

=item $resp_r

A reference to a scalar that can be used to return a reference to a hash containing information about the authentication process. This is UAM-specific.

=back

Error replies:

=over

=item kFPCallNotSupported

Server does not support this command.

=item kFPUserNotAuth

UAM failed (the specified old password doesn't match) or no user is logged in yet for the specified session.

=item kFPBadUAM

Specified UAM is not a UAM that FPChangePassword supports.

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPParamErr

User name is null, exceeds the UAM's user name length limit, or does not exist.

=item kFPPwdSameErr

User attempted to change his or her password to the same password that he or she previously had. This error occurs only if the password expiration feature is enabled on the server.

=item kFPPwdTooShortErr

User password is shorter than the server's minimum password length, or user attempted to change password to a password that is shorter than the server's minimum password length.

=item kFPPwdPolicyErr

New password does not conform to the server's password policy.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPChangePassword { # {{{1
    my ($self, $UAM, $UserName, $UserAuthInfo, $resp_r) = @_;
    DEBUG('called ', (caller(0))[3]);

    if (ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF') {
        $resp_r = \q//;
    }

    my $msg = pack('CxC/a*x![s]C/a*x![s]a*', kFPChangePassword, $UAM,
            $UserName, $UserAuthInfo);
    return $self->SendAFPMessage($msg, $resp_r);
} # }}}1

=item FPCloseDir()

Closes a directory and invalidates its Directory ID.

Deprecated; variable directory IDs are no longer supported.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Directory ID.

=back

Error replies:

=over

=item kFPParamErr

The session reference number, Volume ID, or Directory ID is null or invalid.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPCloseDir { # {{{1
    my ($self, $VolumeID, $DirectoryID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN', kFPCloseDir, $VolumeID,
            $DirectoryID));
} # }}}1

=item FPCloseDT()

Close a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $DTRefNum

Desktop database reference number.

=back

Error replies:

=over

=item kFPParamErr

Session reference number or Desktop database reference number was invalid.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPCloseDT { # {{{1
    my($self, $DTRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseDT, $DTRefNum));
} # }}}1

=item FPCloseFork()

Closes a fork.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $OForkRefNum

Open fork reference number.

=back

Error replies:

=over

=item kFPParamErr

The session reference number or open fork number is null or invalid.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPCloseFork { # {{{1
    my($self, $OForkRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseFork, $OForkRefNum));
} # }}}1

=item FPCloseVol()

Close a volume.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=back

Error replies:

=over

=item kFPParamErr

Session reference number or Volume ID is null or invalid.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPCloseVol { # {{{1
    my ($self, $VolumeID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseVol, $VolumeID));
} # }}}1

=item FPCopyFile()

Copies a file from one location to another on the same file server.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item SourceVolumeID

Source Volume ID.

=item SourceDirectoryID

Source ancestor Directory ID.

=item DestVolumeID

Destination Volume ID.

=item DestDirectoryID

Destination ancestor Directory ID.

=item SourcePathType

Type of names in C<SourcePathname>. See L</"Path Type Constants"> for
possible values.

=item SourcePathname

Pathname of the file to be copied (cannot be null).

=item DestPathType

Type of names in C<DestPathname>. See L</"Path Type Constants"> for
possible values.

=item DestPathname

Pathname to the destination parent directory (may be null).

=item NewType

Type of names in C<NewName>. See L</"Path Type Constants"> for
possible values.

=item NewName

Name to be given to the copy (may be null).

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to read the file
or write to the destination.

=item kFPCallNotSupported

Server does not support this command.

=item kFPDenyConflict

File cannot be opened for Read, DenyWrite.

=item kFPDiskFull

No more space exists on the destination volume.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectExists

File or directory of the name specified by C<NewName> already exists
in the destination parent directory.

=item kFPObjectNotFound

The source file does not exist; ancestor directory is unknown.

=item kFPObjectTypeErr

Source parameters point to a directory.

=item kFPParamErr

Session reference number, Volume ID, or a pathname type is unknown;
source or destination pathname is invalid.

=back

=cut
sub FPCopyFile { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('SourceVolumeID must be provided')
            unless exists $options{'SourceVolumeID'};
    croak('SourceDirectoryID must be provided')
            unless exists $options{'SourceDirectoryID'};
    croak('DestVolumeID must be provided')
            unless exists $options{'DestVolumeID'};
    croak('DestDirectoryID must be provided')
            unless exists $options{'DestDirectoryID'};
    croak('SourcePathType must be provided')
            unless exists $options{'SourcePathType'};
    croak('SourcePathname must be provided')
            unless exists $options{'SourcePathname'};
    croak('DestPathType must be provided')
            unless exists $options{'DestPathType'};
    croak('DestPathname must be provided')
            unless exists $options{'DestPathname'};
    croak('NewType must be provided')
            unless exists $options{'NewType'};
    croak('NewName must be provided')
            unless exists $options{'NewName'};

    my $msg = pack('CxnNnNa*a*a*', kFPCopyFile,
            @options{'SourceVolumeID', 'SourceDirectoryID',
                     'DestVolumeID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPCreateDir()

Creates a new directory.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item DirectoryID

Ancestor Directory ID.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname, including the name of the new directory (cannot be null).

=back

Returns:

A scalar indicating the error code from the call. Upon success, the return
is a list, containing both the error code and the Directory ID of the
newly created directory.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPDiskFull

No more space exists on the volume.

=item kFPFlatVol

Volume is flat and does not support directories.

=item kFPMiscErr

A non-AFP error occurred.

=item kFPObjectNotFound

Ancestor directory is unknown.

=item kFPObjectExists

File or directory of the specified name already exists.

=item kFPParamErr

Session reference number, Volume ID, or pathname is null or invalid.

=item kFPVolLocked

Destination volume is read-only.

=back

=cut
sub FPCreateDir { # {{{1
    my($self, %options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CxnNa*', kFPCreateDir,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})), \$resp);
    return($rc, unpack('N', $resp))
            if $rc == kFPNoErr and wantarray();
    return $rc;
} # }}}1

=item FPCreateFile()

Creates a new file.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item Flag

Bit 7 of the Flag parameter is the C<CreateFlag> bit, where 0 indicates
a soft create and 1 indicates a hard create.

=item VolumeID

Volume ID.

=item DirectoryID

Ancestor directory ID.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname, including the name of the new file (cannot be null).

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPDiskFull

No more space exists on the volume.

=item kFPFileBusy

If attempting a hard create, the file already exists and is open.

=item kFPMiscErr

A non-AFP error occurred.

=item kFPObjectExists

If attempting a soft create, a file of the specified name already exists.

=item kFPObjectNotFound

Ancestor directory is unknown.

=item kFPVolLocked

Destination volume is read-only.

=item kFPParamErr

Session reference number, Volume ID, or pathname is null or invalid.

=back

=cut
sub FPCreateFile { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flag'} ||= 0;
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    return $self->SendAFPMessage(pack('CCnNa*', kFPCreateFile,
            @options{'Flag', 'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})));
} # }}}1

=item FPCreateID()

Creates a unique File ID for a file.

Deprecated; Mac OS X AFP clients assume that all files and directories
have assigned IDs that are unique and are not reused when the item is
deleted.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item DirectoryID

Directory ID containing the referenced file.

=item PathType

Type of names in C<Pathname>. See L</Path Type Constants> for possible
values.

=item Pathname

Name of the file that is the target of the File ID (that is, the filename
of the file for which a File ID is being created).

=item $resp_r

A reference to a scalar which will contain the new File ID.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, and the new File ID.

Error replies:

=over

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Target file does not exist.

=item kFPObjectTypeErr

Object defined was a directory, not a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
pathname is null or bad.

=item kFPVolLocked

Destination volume is read-only.

=back

=cut
sub FPCreateID {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $resp;
    my $msg = pack('CxnNa*', kFPCreateID,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    return($rc, unpack('N', $resp));
}

=item FPDelete()

Deletes a file or directory.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Ancestor Directory ID.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname of the file or directory to be deleted (may be null if a
directory is to be deleted).

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPDirNotEmpty

Directory is not empty.

=item kFPFileBusy

The file to be deleted is open by another process.

=item kFPMiscErr

A non-AFP error occurred.

=item kFPObjectLocked

File or directory is marked DeleteInhibit.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPObjectTypeErr

Object defined was a directory, not a file.

=item kFPVolLocked

Volume is read=only.

=item kFPParamErr

Session reference number, Volume ID, or pathname is null or invalid.

=back

=cut
sub FPDelete { # {{{1
    my($self, $VolumeID, $DirectoryID, $PathType, $Pathname) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnNa*', kFPDelete, $VolumeID,
            $DirectoryID, PackagePath($PathType, $Pathname)));
} # }}}1

=item FPDeleteID()

Invalidates all instances of the specified File ID.

Deprecated; Mac OS X AFP clients assume that all files and directories
have assigned IDs that are unique and are not reused when the item is
deleted.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $FileID

File ID that is to be deleted.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPCallNotSupported

Server does not support this command.

=item kFPIDNotFound

File ID was not found. (No file thread exists.)

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Target file does not exist.

=item kFPObjectTypeErr

Object defined was a directory, not a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
pathname is null or bad.

=item kFPVolLocked

Destination volume is read-only.

=back

=cut
sub FPDeleteID {
    my($self, $VolumeID, $FileID) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxnN', kFPDeleteID, $VolumeID, $FileID));
}

=item FPDisconnectOldSession()

Disconnects an old session and transfers its resources to a new session.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Type

Reserved; currently always zero (0).

=item $Token

Token previously obtained by calling L</FPGetSessionToken>.

=back

Error replies:

=over

=item kFPCallNotSupported

Server does not support this command.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPDisconnectOldSession {
    my($self, $Type, $Token) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN/a', kFPDisconnectOldSession, $Type,
            $Token));
}

=item FPEnumerate()

List the contents of a directory.

Deprecated; use C<FPEnumerateExt2()> instead.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item DirectoryID

Identifier for the directory to list.

=item FileBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a file. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<FileBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::FileParms>.

=item DirectoryBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a directory. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<DirectoryBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::DirParms>.

=item ReqCount

Maximum number of C<ResultsRecord> structures for which information is
to be returned.

=item StartIndex

Directory offspring index. (Starts at 1.)

=item MaxReplySize

Maximum size of the reply block.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to the desired directory.

=item Entries_ref

A reference to a scalar that can be used to contain an array of parsed
data structures containing information about remote files.

 [
   {
     'CreateDate' => 1231627038,
     'ModDate' => 1231627038,
     'UTF8Hint' => 0,
     'DataForkLen' => 2987,
     'NodeID' => 6233527,
     'UnixGID' => 501,
     'UTF8Name' => 'rename.pl',
     'FileIsDir' => 0,
     'UnixPerms' => 33261,
     'ParentDirID' => 2,
     'UnixUID' => 501,
     'UnixAccessRights' => 2265121543
   },
   ...
 ]

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that cannot be retrieved by this command, an attempt was made to retrieve the Directory ID for a directory on a variable Directory ID volume, or both bitmaps are empty.

=item kFPDirNotFound

Input parameters do not point to an existing directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

No more offspring exist to be enumerated.

item kFPObjectTypeErr

Input parameters point to a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown, pathname is bad, or MaxReplySize is too small to hold a single offspring structure.

=back

=cut
sub FPEnumerate { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'FileBitmap'} ||= 0;
    $options{'DirectoryBitmap'} ||= 0;
    croak('ReqCount must be provided')
            unless exists $options{'ReqCount'};
    croak('StartIndex must be provided')
            unless exists $options{'StartIndex'};
    croak('MaxReplySize must be provided')
            unless exists $options{'MaxReplySize'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    # FIXME: Maybe we should just return this rather than having to take a
    # ref and screw with that?
    croak('Entries_ref must be a scalar ref')
            unless ref($options{'Entries_ref'}) eq 'SCALAR'
                or ref($options{'Entries_ref'}) eq 'REF';

    my $msg = pack('CxnNnnnnna*', kFPEnumerate,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    my($FileBitmap, $DirectoryBitmap, $ActualCount, $ReplyBody)
            = unpack('nnna*', $resp);
    my $Entry;
    my @results = ();
    for my $i (0 .. $ActualCount - 1) {
        my $length = unpack('C', $ReplyBody);
        ($Entry, $ReplyBody) = unpack('a[' . $length . ']a*', $ReplyBody);

        # first byte indicates entry length, next byte contains the 
        # isFileDir bit
        my ($IsFileDir, $OffspringParameters) = unpack('xCa*', $Entry);
        if ($IsFileDir == 0x80) {
            # This child is a directory
            push(@results, _ParseDirParms($DirectoryBitmap, $OffspringParameters));
        }
        else {
            # This child is a file
            push(@results, _ParseFileParms($FileBitmap, $OffspringParameters));
        }
    }
    ${$options{'Entries_ref'}} = [@results];
    return $rc;
} # }}}1

=item FPEnumerateExt()

Lists the contents of a directory.

Deprecated; use C<FPEnumerateExt2()> instead.

Arguments are passed as key-value pair for this method.

Arguments:

=over

=item VolumeID

Volume ID.

=item DirectoryID

Identifier for the directory to list.

=item FileBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a file. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<FileBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::FileParms>.

=item DirectoryBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a directory. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<DirectoryBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::DirParms>.

=item ReqCount

Maximum number of C<ResultsRecord> structures for which information is
to be returned.

=item StartIndex

Directory offspring index. (Starts at 1.)

=item MaxReplySize

Maximum size of the reply block.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to the desired directory.

=item Entries_ref

A reference to a scalar that can be used to contain an array of parsed
data structures containing information about remote files.

 [
   {
     'CreateDate' => 1231627038,
     'ModDate' => 1231627038,
     'UTF8Hint' => 0,
     'DataForkLen' => 2987,
     'NodeID' => 6233527,
     'UnixGID' => 501,
     'UTF8Name' => 'rename.pl',
     'FileIsDir' => 0,
     'UnixPerms' => 33261,
     'ParentDirID' => 2,
     'UnixUID' => 501,
     'UnixAccessRights' => 2265121543
   },
   ...
 ]

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that cannot be retrieved by this command, an attempt was made to retrieve the Directory ID for a directory on a variable Directory ID volume, or both bitmaps are empty.

=item kFPDirNotFound

Input parameters do not point to an existing directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

No more offspring exist to be enumerated.

=item kFPObjectTypeErr

Input parameters point to a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown, pathname is bad, or MaxReplySize is too small to hold a single offspring structure.

=back

=cut
sub FPEnumerateExt { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'FileBitmap'} ||= 0;
    $options{'DirectoryBitmap'} ||= 0;
    croak('ReqCount must be provided')
            unless exists $options{'ReqCount'};
    croak('StartIndex must be provided')
            unless exists $options{'StartIndex'};
    croak('MaxReplySize must be provided')
            unless exists $options{'MaxReplySize'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    # FIXME: Maybe we should just return this rather than having to take a
    # ref and screw with that?
    croak('Entries_ref must be a scalar ref')
            unless ref($options{'Entries_ref'}) eq 'SCALAR'
                or ref($options{'Entries_ref'}) eq 'REF';

    my $msg = pack("CxnNnnnnna*", kFPEnumerateExt,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    my($FileBitmap, $DirectoryBitmap, $ActualCount, $ReplyBody)
            = unpack('nnna*', $resp);
    my $Entry;
    my @results = ();
    for my $i (0 .. $ActualCount - 1) {
        my $length = unpack('n', $ReplyBody);
        ($Entry, $ReplyBody) = unpack('a[' . $length . ']a*', $ReplyBody);

        # first 2 bytes indicate entry length, next byte contains the 
        # isFileDir bit, next byte is a pad
        my ($IsFileDir, $OffspringParameters) = unpack('xxCxa*', $Entry);
        if ($IsFileDir == 0x80) { # This child is a directory
            push(@results, _ParseDirParms($DirectoryBitmap, $OffspringParameters));
        }
        else { # This child is a file
            push(@results, _ParseFileParms($FileBitmap, $OffspringParameters));
        }
    }
    ${$options{'Entries_ref'}} = [@results];
    return $rc;
} # }}}1

=item FPEnumerateExt2()

List the contents of a directory.

Arguments are passed as key-value pair for this method.

Arguments:

=over

=item VolumeID

Volume ID.

=item DirectoryID

Identifier for the directory to list.

=item FileBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a file. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<FileBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::FileParms>.

=item DirectoryBitmap

Bitmap describing the parameters to return if the enumerated offspring is
a directory. Set the bit that corresponds to each desired parameter. This
bitmap is the same as the C<DirectoryBitmap> parameter of the
L</FPGetFileDirParms> command and can be null. For bit definitions for
this bitmap, see L<Net::AFP::DirParms>.

=item ReqCount

Maximum number of C<ResultsRecord> structures for which information is
to be returned.

=item StartIndex

Directory offspring index. (Starts at 1.)

=item MaxReplySize

Maximum size of the reply block.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to the desired directory.

=item Entries_ref

A reference to a scalar that can be used to contain an array of parsed
data structures containing information about remote files.

 [
   {
     'CreateDate' => 1231627038,
     'ModDate' => 1231627038,
     'UTF8Hint' => 0,
     'DataForkLen' => 2987,
     'NodeID' => 6233527,
     'UnixGID' => 501,
     'UTF8Name' => 'rename.pl',
     'FileIsDir' => 0,
     'UnixPerms' => 33261,
     'ParentDirID' => 2,
     'UnixUID' => 501,
     'UnixAccessRights' => 2265121543
   },
   ...
 ]

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that cannot be retrieved by this command, an attempt was made to retrieve the Directory ID for a directory on a variable Directory ID volume, or both bitmaps are empty.

=item kFPDirNotFound

Input parameters do not point to an existing directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

No more offspring exist to be enumerated.

=item kFPObjectTypeErr

Input parameters point to a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown, pathname
is bad, or MaxReplySize is too small to hold a single offspring structure.

=back

=cut
sub FPEnumerateExt2 { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'FileBitmap'} ||= 0;
    $options{'DirectoryBitmap'} ||= 0;
    croak('ReqCount must be provided')
            unless exists $options{'ReqCount'};
    croak('StartIndex must be provided')
            unless exists $options{'StartIndex'};
    croak('MaxReplySize must be provided')
            unless exists $options{'MaxReplySize'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    # FIXME: Maybe we should just return this rather than having to take a
    # ref and screw with that?
    croak('Entries_ref must be a scalar ref')
            unless ref($options{'Entries_ref'}) eq 'SCALAR'
                or ref($options{'Entries_ref'}) eq 'REF';

    my $msg = pack('CxnNnnnNNa*', kFPEnumerateExt2,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    my($FileBitmap, $DirectoryBitmap, $ActualCount, $ReplyBody)
            = unpack('nnna*', $resp);
    my $Entry;
    my @results = ();
    for my $i (0 .. $ActualCount - 1) {
        my $length = unpack('n', $ReplyBody);
        ($Entry, $ReplyBody) = unpack('a[' . $length . ']a*', $ReplyBody);

        # first 2 bytes indicate entry length, next byte contains the 
        # isFileDir bit, next byte is a pad
        my ($IsFileDir, $OffspringParameters) = unpack('x[2]Cxa*', $Entry);
        if ($IsFileDir == 0x80) { # This child is a directory
            push(@results, _ParseDirParms($DirectoryBitmap, $OffspringParameters));
        }
        else { # This child is a file
            push(@results, _ParseFileParms($FileBitmap, $OffspringParameters));
        }
    }
    ${$options{'Entries_ref'}} = [@results];
    return $rc;
} # }}}1

=item FPExchangeFiles()

Exchanges file metadata between two files.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item SourceDirectoryID

Identifier of the directory containing the source file.

=item DestDirectoryID

Identifier of the directory containing the destination file.

=item SourcePathType

Type of names in C<SourcePathname>. See L</"Path Type Constants"> for
possible values.

=item SourcePathname

Pathname of the source file.

=item DestPathType

Type of names in C<SourcePathname>. See L</"Path Type Constants"> for
possible values.

=item DestPathname

Pathname of the destination file.

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBadIDErr

File ID is not valid.

=item kFPCallNotSupported

Server does not support this command.

=item kFPIDNotFound

File ID was not found. (No file thread exists.)

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectTypeErr

Object defined was a directory, not a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown; pathname
is null or bad.

=back

=cut
sub FPExchangeFiles {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('SourceDirectoryID must be provided')
            unless exists $options{'SourceDirectoryID'};
    croak('DestDirectoryID must be provided')
            unless exists $options{'DestDirectoryID'};
    croak('SourcePathType must be provided')
            unless exists $options{'SourcePathType'};
    croak('SourcePathname must be provided')
            unless exists $options{'SourcePathname'};
    croak('DestPathType must be provided')
            unless exists $options{'DestPathType'};
    croak('DestPathname must be provided')
            unless exists $options{'DestPathname'};

    my $msg = pack('CxnNNa*a*', kFPExchangeFiles,
            @options{'VolumeID', 'SourceDirectoryID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}));
    return $self->SendAFPMessage($msg);
}

=item FPFlush()

Writes any volume data that has been modified.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=back

Error replies:

=over

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference number or Volume ID is unknown.

=back

=cut
sub FPFlush { # {{{1
    my ($self, $VolumeID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPFlush, $VolumeID));
} # }}}1

=item FPFlushFork()

Write any data buffered from previous write commands.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $OForkRefNum

Open fork reference number.

=back

Error replies:

=over

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference number or fork reference number is unknown.

=back

=cut
sub FPFlushFork { # {{{1
    my ($self, $OForkRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPFlushFork, $OForkRefNum));
} # }}}1

=item FPGetACL()

Gets the access control list for a file or directory.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume identifier.

=item DirectoryID

Directory identifier.

=item Bitmap

Bits that specify the values that are to be obtained. Specify
C<kFileSec_UUID> to get the UUID of the specified file or directory.
Specify C<kFileSec_GRPUUID> to get the Group UUID of the specified
file or directory, or specify kFileSec_ACL to get the ACL of the
specified file or directory. For declarations of these constants,
see L<Net::AFP::ACL/Access Control List Bitmap>.

=item MaxReplySize

Reserved. Set this parameter to zero.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname of the file or directory for which the access control list (ACL)
is to be obtained.

=back

Returns:

A scalar indicating the error code from the call; upon success, a list
containing the error code, followed by key-value pairs containing ACL
related fields about the requested file, like the following:

 (
   'acl_ace' => [
                  {
                    'ace_flags' => 1,
                    'ace_rights' => 4,
                    'ace_applicable' => 'abcdefab-cdef-abcd-efab-cdef00000050'
                  },
                  ...
                ],
   'Bitmap' => 7,
   'acl_flags' => 0,
   'UUID' => 'abcdefab-cdef-abcd-efab-cdef00000050',
   'GRPUUID' => 'abcdefab-cdef-abcd-efab-cdef00000050',
 )

Error replies:

=over

=item kFPAccessDenied

User does not have the access rights required to get the ACL for the
specified file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPGetACL { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= kFileSec_ACL;
    $options{'MaxReplySize'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNnNa*', kFPGetACL,
            @options{'VolumeID', 'DirectoryID', 'Bitmap', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    my %rvals;
    ($rvals{'Bitmap'}, $resp) = unpack('na*', $resp);

    if ($rvals{'Bitmap'} & kFileSec_UUID) {
        ($rvals{'UUID'}, $resp) = unpack('a[16]a*', $resp);
        $rvals{'UUID'} = uuid_unpack($rvals{'UUID'});
    }

    if ($rvals{'Bitmap'} & kFileSec_GRPUUID) {
        ($rvals{'GRPUUID'}, $resp) = unpack('a[16]a*', $resp);
        $rvals{'GRPUUID'} = uuid_unpack($rvals{'GRPUUID'});
    }

    if ($rvals{'Bitmap'} & kFileSec_ACL) {
        my $acl_entrycount;
        ($acl_entrycount, $rvals{'acl_flags'}, $resp) = unpack('NNa*', $resp);
        my @entries = unpack('(a[16]NN)[' . $acl_entrycount . ']', $resp);
        my @acl_ace = ();
        for my $i (0 .. $acl_entrycount - 1) {
            $acl_ace[$i] = {
                             'ace_applicable'   => uuid_unpack(shift(@entries)),
                             'ace_flags'        => shift(@entries),
                             'ace_rights'       => shift(@entries),
                           };
        }
        $rvals{'acl_ace'} = [ @acl_ace ];
    }
    return($rc, %rvals);
} # }}}1

=item FPGetAPPL()

Retrieves an APPL mapping from a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number.

=item FileCreator

File creator of the application corresponding to the APPL mapping
to be retrieved.

=item Index

Index of the APPL mapping to be retrieved.

=item Bitmap

Parameters to retrieve about the application to be used to open the file
with the indicated Creator ID. See C<Net::AFP::FileParms> for the parameter
bits which can be set.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
will be returned containing the error call, and a set of key/value pairs
with the returned parameters.

Error replies:

=over

=item kFPParamErr

Session reference number or Desktop database reference was unknown.

=item kFPItemNotFound

No entries in the Desktop database matched the given parameters.

=item kFPBitmapErr

A parameter was requested which could not be retrieved using this operation.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetAPPL {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('FileCreator must be provided')
            unless exists $options{'FileCreator'};
    croak('APPLIndex must be provided')
            unless exists $options{'APPLIndex'};
    $options{'Bitmap'} ||= 0;

    my $msg = pack('CxnNnn', kFPGetAPPL,
            @options{'DTRefNum', 'FileCreator', 'APPLIndex', 'Bitmap'});

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    my($Bitmap_n, $APPLTag, $data) = unpack('nNa*', $resp);
    my $info = _ParseFileParms($Bitmap_n, $data);
    my %rvals = (
                  'Bitmap'          => $Bitmap_n,
                  'APPLTag'         => $APPLTag,
                  'FileParameters'  => $info,
                );
    return($rc, %rvals);
}

=item FPGetAuthMethods()

Get the UAMs that an Open Directory domain supports.

Deprecated (?).

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Flags

Flags providing additional information. (No flags are currently defined.)

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname of the Open Directory domain for which UAMs are to be obtained.

=item $resp_r

A reference to a scalar that can be used to contain a hash reference, which
will contain the list of supported UAMs for the given Open Directory domain.

 {
   'Flags' => 0,
   'UAMStrings' => [
                     'DHX2',
                     ...
                   ],
 }

=back

Error replies:

=over

=item kFPObjectNotFound

The specified Open Directory server was not known.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetAuthMethods { # {{{1
    my($self, $Flags, $PathType, $Pathname, $resp_r) = @_;
    DEBUG('called ', (caller(0))[3]);

    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
    my $msg = pack('CxCa*', kFPGetAuthMethods, $Flags,
            PackagePath($PathType, $Pathname));
    my($resp, @UAMStrings);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    ($Flags, @UAMStrings) = unpack('CC/(C/a)', $resp);
    ${$resp_r} = { 'Flags' => $Flags, 'UAMStrings' => [ @UAMStrings ] };
    return $rc;
} # }}}1

=item FPGetComment()

Gets the comment associated with a file or directory from the volume's
Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number.

=item DirectoryID

Directory ID.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
will be returned, containing the error code and a string containing the
comment text (if any was present) for the referenced file.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPItemNotFound

No comment was found in the Desktop database.

=item kFPParamErr

Session reference number or Desktop database reference number is unknown.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetComment { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNa*', kFPGetComment,
            @options{'DTRefNum', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    return($rc, unpack('C/a', $resp));
} # }}}1

=item FPGetExtAttr()

Gets the value of an extended attribute.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume identifier.

=item DirectoryID

Directory identifier.

=item Bitmap

Bitmap specifying the desired behavior when getting the value of an
extended attribute. For this command, only kAttrDontFollow is valid.
For details, see L<Net::AFP::ExtAttrs/"Extended Attributes Bitmap">.

=item Offset

Always zero; reserved for future use.

=item ReqCount

Always -1; reserved for future use.

=item MaxReplySize

Size in bytes of the reply that your application can handle; set to zero
to get the size of the reply without actually getting the attributes.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory.

=item Name

UTF-8 encoded name of the extended attribute whose value is to be
obtained.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by key-value pairs containing the
requested information about the supplied extended attribute.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to get the contents of
an extended attribute for the specified file or directory.

=item kFPBitmapErr

Bitmap is null or specifies a value that is invalid for this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPGetExtAttr { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'VolumeID'};
    $options{'Bitmap'} ||= 0;
    $options{'Offset'} ||= 0;
    $options{'ReqCount'} ||= -1;
    $options{'MaxReplySize'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('Name must be provided')
            unless exists $options{'Name'};

    my $msg = pack('CxnNnNNNNNa*x![s]n/a*', kFPGetExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            ll_convert($options{'Offset'}),
            ll_convert($options{'ReqCount'}),
            $options{'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{'Name'})));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    my %rvals;
    if ($options{'MaxReplySize'} > 0) {
        @rvals{'Bitmap', 'AttributeData'} = unpack('nN/a*', $resp);
    }
    else {
        @rvals{'Bitmap', 'DataLength'} = unpack('nN', $resp);
    }
    return($rc, %rvals);
} # }}}1

=item FPGetFileDirParms()

Gets the parameters for a file or a directory.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item DirectoryID

Directory ID.

=item FileBitmap

Bitmap describing the parameters to return for a file. Set the bit that
corresponds to each desired parameter. For the bit definitions of this
bitmap, see L<Net::AFP::FileParms>.

=item DirectoryBitmap

Bitmap describing the parameters to return for a directory. Set the bit
that corresponds to each desired parameter. For the bit definitions of
this bitmap, see L<Net::AFP::DirParms>.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory.

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by key-value pairs containing the
requested parameters about the indicated file or directory.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that cannot be obtained with this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
pathname is invalid.

=back

=cut
sub FPGetFileDirParms { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'FileBitmap'} ||= 0;
    $options{'DirectoryBitmap'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNnna*', kFPGetFileDirParms,
            @options{'VolumeID','DirectoryID','FileBitmap','DirectoryBitmap'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    return($rc, _ParseFileDirParms($resp));
} # }}}1

=item FPGetForkParms()

Get the parameters for a fork.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $OForkRefNum

Open fork reference number.

=item $Bitmap

Bitmap describing the parameters to be returned. Set the bits that
correspond to each desired parameter. This bitmap is the same as the
C<FileBitmap> parameter of the L</FPGetFileDirParms> command. For
bit definitions for this bitmap, see L<Net::AFP::FileParms>.

=item $resp_r

A scalar reference which will contain a hash reference containing the information indicated in $Bitmap on success.

=back

Error replies:

=over

=item kFPParamErr

The open fork reference number provided is invalid.

=item kFPBitmapErr

The request attempted to get information about the opened file's other fork.

=back

=cut
sub FPGetForkParms { # {{{1
    my ($self, $OForkRefNum, $Bitmap, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', kFPGetForkParms, $OForkRefNum,
            $Bitmap), \$resp);
    return $rc unless $rc == kFPNoErr;
    ${$resp_r} = _ParseFileParms(unpack('na*', $resp));
    return $rc;
} # }}}1

=item FPGetIcon()

Gets an icon from the Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item DTRefNum

Desktop database reference number.

=item FileCreator

File creator associated with the icon that is to be added.

=item FileType

File type associated with the icon that is to be added.

=item IconType

Type of icon that is to be added.

=item Length

Number of bytes the caller expects the icon bitmap to require in the
reply block.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by a string containing the binary
icon data.

Error replies:

=over

=item kFPParamErr

Session reference number or Desktop database reference number is
unknown.

=item kFPItemNotFound

No icon corresponding to the input parameters was found in the
Desktop database.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetIcon {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('FileCreator must be provided')
            unless exists $options{'FileCreator'};
    croak('FileType must be provided')
            unless exists $options{'FileType'};
    croak('IconType must be provided')
            unless exists $options{'IconType'};
    croak('Length must be provided')
            unless exists $options{'Length'};

    my $msg = pack('CxnNNCxn', kFPGetIcon,
            @options{'DTRefNum', 'FileCreator', 'FileType', 'IconType',
                     'Length'});
    croak('Need to accept returned list') unless wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
}

=item FPGetIconInfo()

Gets icon information from the Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $DTRefNum

Desktop database reference number.

=item $FileCreator

File creator associated with the icon that is to be added.

=item $IconIndex

Index of the requested icon.

=item $resp_r

A reference to a scalar which will contain a hash with information
about the indicated icon.

=back

Error replies:

=over

=item kFPParamErr

Session reference number or Desktop database reference number is
unknown.

=item kFPItemNotFound

No icon corresponding to the input parameters was found in the
Desktop database.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetIconInfo {
    my($self, $DTRefNum, $FileCreator, $IconIndex, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
    
    my $resp;
    my $msg = pack('CxnNn', kFPGetIconInfo, $DTRefNum, $FileCreator,
            $IconIndex);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) unless $rc == kFPNoErr;
    ${$resp_r} = {};
    @{${$resp_r}}{'IconTag', 'FileType', 'IconType', 'Size'} =
            unpack('NNCxn', $resp);
    return $rc;
}

=item FPGetSessionToken()

Gets a session token.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Type

The value of this parameter is C<kLoginWithoutID> (0) if the client supports
an earlier version of AFP that does not send an C<$IDLength> and an C<$ID>
parameter. If is C<kLoginWithTimeAndID> (3) if the client is sending an
C<$IDLength>, an C<$ID>, and a C<$timeStamp> parameter and the client wants
its old session to be discarded. It is C<kReconnWithTimeAndID> (4) if the
client has just finished a successful reconnect, is sending an C<$IDLength>,
an C<$ID>, and a C<$timeStamp> parameter, and wants to be updated with the
C<$ID> parameter. It is C<kGetKerberosSessionKey> (8) if the client is
logging in using Kerberos v5. See L<Net::AFP::TokenTypes> for the
definitions of the constants for this parameter.

=item $timeStamp

Optional time stamp specified only if the value of C<$ID> is
C<kLoginWithTimeAndID> or C<kReconnWithTimeAndID>.

=item $ID

A client-defined value that uniquely identifies this session.

=item $resp_r

A scalar reference which will be assigned a scalar reference containing
the retrieved token data.

=back

Error replies:

=over

=item kFPParamErr

Session reference number is null or invalid.

=item kFPCallNotSupported

Server does not support this command.

=item kFPMiscErr

A non-AFP error occurred.

=back

=cut
sub FPGetSessionToken { # {{{1
    my ($self, $Type, $timeStamp, $ID, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    $ID ||= q//;
    my $pack_mask = 'CxnN';
    my @params = (kFPGetSessionToken, $Type, length($ID));
    if ($Type == kLoginWithTimeAndID || $Type == kReconnWithTimeAndID) {
        $pack_mask .= 'N';
        push(@params, $timeStamp);
    }
    $pack_mask .= 'a*';
    push(@params, $ID);

    my $msg = pack($pack_mask, @params);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    if ($rc == kFPNoErr) {
        ${$resp_r} = unpack('N/a', $resp);
    }
    return $rc;
} # }}}1

=item FPGetSrvrInfo()

Gets information about a server.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $resp_r

A scalar reference which will have a hash reference placed in it,
containing information about the server.

=back

Error replies:

=over

=item kFPNoServer

The server name could not be resolved, or the server would not accept
the connection.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetSrvrInfo { # {{{1
    my ($self, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cx', kFPGetSrvrInfo), \$resp);
    # If the response was not kFPNoErr, the info block will not be present.
    return $rc unless $rc == kFPNoErr;

    ${$resp_r} = _ParseSrvrInfo($resp);
    return $rc;
} # }}}1

=item FPGetSrvrMsg()

Gets a message from a server.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $MessageType

Type of message, where 0 indicates a login message, and 1 indicates a
server message. (Set C<$MessageType> to 1 when the Server Message bit
in the attention code is set.)

=item $MessageBitmap

Bitmap providing additional information. The client sets bit 0 of this
bitmap to indicate it is requesting a message. Starting with AFP 3.0,
the client can set bit 1 of this bitmap to indicate that it supports
UTF-8 messages.

=item $resp_r

A reference to a scalar which will contain the message returned from
the server upon success.

=back

Error replies:

=over

=item kFPCallNotSupported

Server does not support this command.

=item kFPBitmapErr

Flags passed in $MessageBitmap were not recognized.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPGetSrvrMsg { # {{{1
    my($self, $MessageType, $MessageBitmap, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', kFPGetSrvrMsg, $MessageType,
            $MessageBitmap), \$resp);
    return $rc unless $rc == kFPNoErr;
    my ($Length, $ServerMessage);
    if ($MessageBitmap & 0x2) { # bit 1; means send message as UTF8
        ($Length, $MessageType, $MessageBitmap, $ServerMessage) =
                unpack('nnna*', $resp);
        $ServerMessage = compose(decode_utf8($ServerMessage));
    }
    else { # not UTF8, just a plain pstring (?)
        ($MessageType, $MessageBitmap, $ServerMessage) =
                unpack('nnC/a', $resp);
        $Length = length($ServerMessage);
    }
    ${$resp_r} = {
                   'MessageType'    => $MessageType,
                   'MessageBitmap'  => $MessageBitmap,
                   'ServerMessage'  => $ServerMessage,
                   'Length'         => $Length,
                 };
    return $rc;
} # }}}1

=item FPGetSrvrParms()

Get a list of volumes that the server is willing to offer for sharing.
Must be authenticated.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $resp_r

A reference to a scalar that can be used to return a reference to a hash containing information about the server.

=back

Error replies:

=over

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference number or Volume ID is unknown.

=back

=cut
sub FPGetSrvrParms { # {{{1
    my ($self, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cx', kFPGetSrvrParms), \$resp);
    # If the response was not kFPNoErr, the info block will not be present.
    return $rc unless $rc == kFPNoErr;

    my $data = {};
    my ($time, @volinfo) = unpack('NC/(CC/a)', $resp);
    # AFP does not express times since 1 Jan 1970 00:00 GMT, but since 
    # 1 Jan 2000 00:00 GMT (I think GMT, anyway). Good call, Apple...
    ${$data}{'ServerTime'} = long_unconvert($time) + globalTimeOffset;
    ${$data}{'Volumes'} = [];
    while (scalar(@volinfo) > 0) {
        my $flags = shift @volinfo;
        my $volname = shift @volinfo;
        # The documentation from Apple says "HasUNIXPrivs" is the high
        # bit; ethereal seems to think it's the second bit, not the high
        # bit. I'll have to see how to turn that on somewhere to find out.
        # Also, looks like the HasUNIXPrivs bit is gone as of AFP 3.2...
        push(@{${$data}{'Volumes'}}, { 'HasPassword'     => $flags & 0x80,
                                       'HasConfigInfo'   => $flags & 0x01,
                                       'VolName'         => $volname } );
    }
    ${$resp_r} = $data;
    return $rc;
} # }}}1

=item FPGetUserInfo()

Retrieve certain information about a user from an AFP server. Must be
authenticated.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Flags

If the lowest bit (0x1) is set (the C<ThisUser> flag), information is
obtained about the current user and the C<$UserID> field is ignored.

=item $UserID

ID of user for whom information is to be retrieved. (Not valid if the
C<ThisUser> bit is set in the C<$Flags> field.)

This field is deprecated for security reasons. The C<ThisUser> bit should
always be set in the flags field.

=item $Bitmap

Bitmap describing which IDs to retrieve, where bit zero (0x1) is set to get
the user's User ID, bit 1 (0x2) is set to get the user's Primary Group ID,
and bit 2 (0x4) is set to get the user's UUID.

=item $resp_r

A scalar reference to contain a hash ref, which will contain returned data.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to
get information about the specified user.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that can not
be obtained with this command.

=item kFPCallNotSupported

Server does not support this command.

=item kFPItemNotFound

Specified User ID is unknown.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

ThisUser bit is not set.

=item kFPPwdExpiredErr

User's password has expired. User is required to change his or her password.
The user is logged on but can only change his or her password or log out.

=item kFPPwdNeedsChangeErr

User's password needs to be changed. User is required to change his or her
password. The user is logged on but can only change his or her password or
log out.

=back

=cut
sub FPGetUserInfo { # {{{1
    my ($self, $Flags, $UserID, $Bitmap, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CCNn', kFPGetUserInfo, $Flags, $UserID,
            $Bitmap), \$resp);

    return $rc unless $rc == kFPNoErr;
    
    my $rbmp = unpack('n', $resp);
    my $offset = 2;
    ${$resp_r} = {};
    if ($rbmp & 0x1) { # Get User ID bit
        ${$resp_r}{'UserID'} = unpack('x[' . $offset . ']N', $resp);
        $offset += 4;
    }
    if ($rbmp & 0x2) {
        ${$resp_r}{'PrimaryGroupID'} = unpack('x[' . $offset . ']N', $resp);
        $offset += 4;
    }
    if ($rbmp & 0x4) {
        ${$resp_r}{'UUID'} = uuid_unpack(unpack('x['.$offset.']a[16]', $resp));
        $offset += 16;
    }

    return $rc;
} # }}}1

=item FPGetVolParms()

Get the volume parameter information from an AFP server for a volume
previously opened with FPOpenVol(). Must be authenticated.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

The numeric volume ID returned as part of FPOpenVol().

=item $Bitmap

A Volume bitmap. See the Net::AFP::VolParms package.

=item $resp_r

A reference to a scalar that can be used to return
a reference to a hash containing information about
the server.

=back

Error replies:

=over

=item kFPBitmapErr

Attempt was made to retrieve a parameter that can not
be obtained with this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

The session reference number or Volume ID is unknown.

=back

=cut
sub FPGetVolParms { # {{{1
    my($self, $VolumeID, $Bitmap, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', kFPGetVolParms, $VolumeID,
            $Bitmap), \$resp);
    return($rc) unless $rc == kFPNoErr;
    ${$resp_r} = _ParseVolParms($resp);
    return $rc;
} # }}}1

=item FPListExtAttrs()

Gets the names of extended attributes for a file or directory.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume identifier.

=item DirectoryID

Directory identifier.

=item Bitmap

Bitmap describing the desired behavior when getting the names of extended
attributes. For this command C<kAttrDontFollow> is the only valid bit.
For details, see L<Net::AFP::ExtAttrs/"Extended Attributes Bitmap">.

=item ReqCount

Reserved for future use. For AFP 3.2, clients can set this parameter to
any numeric value. Servers should ignore this parameter and return all
extended attribute names.

=item StartIndex

Reserved for future use. For AFP 3.2, set C<$StartIndex> to zero.
Servers should ignore this parameter.

=item MaxReplySize

Size in bytes of the reply that your application can handle, including
the size of the C<$Bitmap> and C<$DataLength> parameters. Set this
parameter to zero to get the size of the reply block that would be
returned without actually getting the names of the extended attributes.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to desired file or directory.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by key-value pairs containing the
returned information about the extended attributes list.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to list the extended
attribute names for the specified file or directory.

=item kFPBitmapErr

Bitmap is null or specifies a value that is invalid for this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPListExtAttrs { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    $options{'ReqCount'} ||= 0;
    $options{'StartIndex'} ||= 0;
    $options{'MaxReplySize'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNnnNNa*', kFPListExtAttrs,
            @options{'VolumeID', 'DirectoryID', 'Bitmap', 'ReqCount',
                     'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    my %rvals;
    if ($options{'MaxReplySize'} > 0) {
        my $names;
        ($rvals{'Bitmap'}, $names) = unpack('nN/a*', $resp);
        $rvals{'AttributeNames'} =
                [ map { compose(decode_utf8($_)) } unpack('(Z*)*', $names) ];
    }
    else {
        @rvals{'Bitmap', 'DataLength'} = unpack('nN', $resp);
    }
    return($rc, %rvals);
} # }}}1

=item FPLogin()

Establishes a session with a server.

Deprecated in AFP 3.x; use C<FPLoginExt()> instead.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $AFPVersion

String indicating which AFP version to use. For possible values, see
L</"AFP Version Strings">.

=item $UAM

String indicating which UAM to use. For possible values, see
L</"AFP UAM Strings">.

=item $UserAuthInfo

UAM-dependent information required to authenticate the user (can be null).
The data type of C<$UserAuthInfo> depends on the UAM specified by C<$UAM>.

=item $resp_r

A reference to a scalar that can be used to return
a reference to a hash containing information
relevant to the login process.

=back

Error replies:

=over

=item kFPAuthContinue

Authentication is not yet complete. (Not an error, just
a status reply.)

=item kFPBadUAM

Specified UAM is unknown.

=item kFPBadVersNum

Server does not support the specified AFP version.

=item kFPCallNotSupported

Server does not support this command.

=item kFPMiscErr

User is already authenticated.

=item kFPNoServer

Server is not responding.

=item kFPPwdExpiredErr

User's password has expired. User is required to change
his or her password. The user is logged on but can only
change his or her password or log out.

=item kFPPwdNeedsChangeErr

User's password needs to be changed. User is required
to change his or her password. The user is logged on
but can only change his or her password or log out.

=item kFPServerGoingDown

Server is shutting down.

=item kFPUserNotAuth

Authentication failed.

=back

=cut
sub FPLogin { # {{{1
    my ($self, $AFPVersion, $UAM, $UserAuthInfo) = @_;

    DEBUG('called ', (caller(0))[3]);
    $UserAuthInfo ||= q//;

    my $msg = pack('CC/a*C/a*a*', kFPLogin, $AFPVersion, $UAM, $UserAuthInfo);
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    
    croak('Need to accept returned list') unless wantarray();
    if ($rc == kFPAuthContinue and length($resp) >= 2) {
        $rvals{'ID'} = unpack('n', $resp);
        if (length($resp) > 2) {
            $rvals{'UserAuthInfo'} = substr($resp, 2);
        }
    }
    return($rc, %rvals);
} # }}}1

=item FPLoginCont()

Continues the login and user authentication process started by a login
command.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $ID

Number returned by a previous call to L</FPLogin>, L</FPLoginExt>, or
L</FPLoginCont>.

=item $UserAuthInfo

UAM-dependent information required to authenticate the user (can be null).
The data type of C<$UserAuthInfo> depends on the UAM that was specified
when L</FPLogin> or L</FPLoginExt> was called.

=item $resp_r

A reference to a scalar that can be used to return
a reference to a hash containing information relevant
to the login process.

=back

Error replies:

=over

=item kFPAuthContinue

Authentication is not yet complete. (Not an error, just
a status reply.)

=item kFPMiscErr

Non-AFP error occurred.

=item kFPNoServer

Server is not responding.

=item kFPParamErr

Authentication failed for an unknown reason.

=item kFPPwdExpiredErr

User's password has expired. User is required to change
his or her password. The user is logged on but can only
change his or her password or log out.

=item kFPPwdNeedsChangeErr

User's password needs to be changed. User is required
to change his or her password. The user is logged on
but can only change his or her password or log out.

=item kFPUserNotAuth

User was not authenticated because the password is
incorrect.

=back

=cut
sub FPLoginCont { # {{{1
    my ($self, $ID, $UserAuthInfo, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    if (ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF') {
        # Hm, was getting "Modification of a read-only value attempted" later
        # in this call apparently because of using \'' to generate a bogus
        # anon scalar. Never got that before.
        $resp_r = *foo{SCALAR};
    }

    $UserAuthInfo ||= q//;

    my $resp;
    # Unlike FPLogin, the pad byte actually does need to be there.
    my $rc = $self->SendAFPMessage(pack('Cxna*', kFPLoginCont, $ID,
            $UserAuthInfo), \$resp);
    
    if (($rc == kFPAuthContinue || $rc == kFPNoErr)
            && defined($resp)) {
        ${$resp_r} = {};
        my $offset = 0;
        if ($rc == kFPAuthContinue) {
            ${$resp_r}->{'ID'} = unpack('n', $resp);
            $offset = 2;
        }
        if (length($resp) > $offset) {
            ${$resp_r}->{'UserAuthInfo'} = substr($resp, $offset);
        }
    }
    return $rc;
} # }}}1

=item FPLoginExt()

Establishes a session with a server using an Open Directory domain.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item $self

An object that is a subclass of Net::AFP.

=item AFPVersion

String indicating which AFP version to use. For possible values, see
L</"AFP Version Strings">.

=item UAM

String indicating which UAM to use. For possible values, see
L</"AFP UAM Strings">.

=item UserNameType

Type of name in C<UserName>; always 3.

=item UserName

UTF-8 encoded name of the user.

=item PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname for the Open Directory domain in which the user specified by
C<$UserName> can be found.

=item UserAuthInfo

UAM-dependent information required to authenticate the user (can be null).
The data type of C<UserAuthInfo> is dependent on the UAM specified by
C<UAM>.

=item $resp_r

A reference to a scalar that can be used to return
a reference to a hash containing information
relevant to the login process.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by key-value pairs containing
information relevant to the login process.

Error replies:

=over

=item kFPAuthContinue

Authentication is not yet complete. (Not an error, just
a status reply.)

=item kFPBadUAM

Specified UAM is unknown.

=item kFPBadVersNum

Server does not support the specified AFP version.

=item kFPCallNotSupported

Server does not support this command.

=item kFPMiscErr

User is already authenticated.

=item kFPNoServer

Server is not responding.

=item kFPPwdExpiredErr

User's password has expired. User is required to change
his or her password. The user is logged on but can only
change his or her password or log out.

=item kFPPwdNeedsChangeErr

User's password needs to be changed. User is required
to change his or her password. The user is logged on
but can only change his or her password or log out.

=item kFPServerGoingDown

Server is shutting down.

=item kFPUserNotAuth

Authentication failed.

=back

=cut
sub FPLoginExt { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flags'} ||= 0;
    croak('AFPVersion must br provided')
            unless exists $options{'AFPVersion'};
    croak('UAM must br provided')
            unless exists $options{'UAM'};
    # The documentation says this should always be UTF8
    $options{'UserNameType'} ||= kFPUTF8Name;
    croak('UserName must br provided')
            unless exists $options{'UserName'};
    # Documentation doesn't say this has to always be UTF8, but it's a safe
    # choice, and generally we don't give a damn
    $options{'PathType'} ||= kFPUTF8Name;
    $options{'Pathname'} ||= q//;
    $options{'UserAuthInfo'} ||= q//;

    my $msg = pack('CxnC/a*C/a*a*a*x![s]a*', kFPLoginExt,
            @options{'Flags', 'AFPVersion', 'UAM'},
            PackagePath(@options{'UserNameType', 'UserName'}, 1),
            PackagePath(@options{'PathType', 'Pathname'}, 1),
            $options{'UserAuthInfo'});
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    
    croak('Need to accept returned list') unless wantarray();
    if ($rc == kFPAuthContinue and length($resp) >= 2) {
        $rvals{'ID'} = unpack('n', $resp);
        if (length($resp) > 2) {
            $rvals{'UserAuthInfo'} = substr($resp, 2);
        }
    }
    return($rc, %rvals);
} # }}}1

=item FPLogout()

Terminates a session with a server.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=back

Error replies:

=over

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

The session reference number is unknown.

=back

=cut
sub FPLogout { # {{{1
    my ($self) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cx', kFPLogout));
} # }}}1

=item FPMapID()

Maps a User ID to a user name or a Group ID to a group name.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Subfunction

Subfunction code. See L<Net::AFP::MapParms/"FPMapID Constants"> for
more information.

=item $ID

The ID to be resolved.

=item $resp_r

A reference to a scalar that can be used to return the resolved name.

=back

Error replies:

=over

=item kFPParamErr

The session number or indicated subfunction is unknown.

=item kFPItemNotFound

The ID passed could not be found.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPMapID { # {{{1
    my($self, $Subfunction, $ID, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $pack_mask = 'CC';
    my @pack_args = (kFPMapID, $Subfunction);
    if ($Subfunction == kUserUUIDToUTF8Name ||
            $Subfunction == kGroupUUIDToUTF8Name) {
        $pack_mask .= 'a[16]';
        $ID = uuid_pack($ID);
    }
    else {
        $pack_mask .= 'N';
    }
    push(@pack_args, $ID);
    my $msg = pack($pack_mask, @pack_args);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    if ($Subfunction == kUserUUIDToUTF8Name ||
            $Subfunction == kGroupUUIDToUTF8Name) {
        ${$resp_r} = {};
        @{${$resp_r}}{'Bitmap', 'NumericID', 'UTF8Name'} =
                unpack('NNn/a', $resp);
        ${${$resp_r}}{'UTF8Name'} = compose(decode_utf8(${${$resp_r}}{'UTF8Name'}));
    }
    else {
        (${$resp_r}) = unpack('C/a', $resp);
    }
    return $rc;
} # }}}1

=item FPMapName()

Maps a user name to a User ID or a group name to a Group ID.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Subfunction

Subfunction code. See L<Net::AFP::MapParms/"FPMapName Constants"> for
more information.

=item $Name

The ID to be resolved.

=item $resp_r

A reference to a scalar that can be used to return the resolved ID.

=back

Error replies:

=over

=item kFPParamErr

The session number or indicated subfunction is unknown.

=item kFPItemNotFound

The name passed could not be found.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPMapName { # {{{1
    my($self, $Subfunction, $Name, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $pack_mask = 'CC';
    if ($Subfunction == kUTF8NameToUserUUID ||
            $Subfunction == kUTF8NameToGroupUUID) {
        $pack_mask .= 'n/a';
        $Name = encode_utf8(decompose($Name));
    }
    else {
        $pack_mask .= 'C/a';
    }
    my $msg = pack($pack_mask, kFPMapName, $Subfunction, $Name);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    if ($Subfunction == kUTF8NameToUserUUID ||
            $Subfunction == kUTF8NameToGroupUUID) {
        ${$resp_r} = uuid_unpack($resp);
    }
    else {
        (${$resp_r}) = unpack('N', $resp);
    }
    return $rc;
} # }}}1

=item FPMoveAndRename()

Moves a CNode to another location on a volume or renames a CNode.

Arguments:

=over

=item VolumeID

The numeric volume ID returned as part of FPOpenVol().

=item SourceDirectoryID

Source ancestor Directory ID.

=item DestDirectoryID

Destination ancestor Directory ID.

=item SourcePathType

Type of names in C<SourcePathname>. See L</"Path Type Constants"> for more information.

=item SourcePathname

Pathname of the file or directory to be moved (may be null if a directory is being moved).

=item DestPathType

Type of names in C<DestPathname>. See L</"Path Type Constants"> for more information.

=item DestPathname

Pathname of the file or directory to be moved to. (may be null if a directory is being moved).

=item NewType

Type of names in C<NewName>. See L</"Path Type Constants"> for more information.

=item NewName

New name of file or directory (may be null).

=back

Returns:

A scalar indicating the error code from the call.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to move or rename the specified file or directory.

=item kFPCantMove

Attempt was made to move a directory into one of its descendent directories.

=item kFPInsideSharedErr

Directory being moved contains a share point and is being moved into a directory that is shared or is the descendent of a directory that is shared.

=item kFPInsideTrashErr

Shared directory is being moved into the Trash; a directory is being moved to the trash and it contains a shared folder.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectExists

File or directory having the same name specified by C<$NewName> already exists.

=item kFPObjectLocked

Directory being moved, renamed or moved and renamed is marked RenameInhibit; file being moved and renamed is marked RenameInhibit.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown; a pathname or C<$NewName> is invalid.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
# Note that there is no mechanism here for returning a value from this
# call; I'm not sure there ever was one, the docs seem pretty wishy-washy
# about this, and so far I'm not seeing anything in packet dumps to
# indicate there ever is one. Going back to "Inside AppleTalk", there
# doesn't seem to be anything returned other than the status code, so
# I'm going to assume from here on out that that's the case.
sub FPMoveAndRename { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('SourceDirectoryID must be provided')
            unless exists $options{'SourceDirectoryID'};
    croak('DestDirectoryID must be provided')
            unless exists $options{'DestDirectoryID'};
    croak('SourcePathType must be provided')
            unless exists $options{'SourcePathType'};
    croak('SourcePathname must be provided')
            unless exists $options{'SourcePathname'};
    croak('DestPathType must be provided')
            unless exists $options{'DestPathType'};
    croak('DestPathname must be provided')
            unless exists $options{'DestPathname'};
    croak('NewType must be provided')
            unless exists $options{'NewType'};
    croak('NewName must be provided')
            unless exists $options{'NewName'};

    my $msg = pack('CxnNNa*a*a*', kFPMoveAndRename,
            @options{'VolumeID', 'SourceDirectoryID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc;
} # }}}1

=item FPOpenDir()

Opens a directory on a variable Directory ID volume and returns its
Directory ID.

Deprecated in Mac OS X.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item VolumeID

Volume ID.

=item DirectoryID

Ancestor Directory ID.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname of the file or directory to be moved (may be null if a directory
is being moved).

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by the returned Directory ID.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to open the directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing directory.

=item kFPObjectTypeErr

Input parameters point to a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown; a
pathname is invalid.

=back

=cut
sub FPOpenDir { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CxnNa*', kFPOpenDir,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})), \$resp);
    return $rc unless $rc == kFPNoErr;
    croak('Need to accept returned list') unless wantarray();
    return($rc, unpack('N', $resp));
} # }}}1

=item FPOpenDT()

Opens the Desktop database on a particular volume.

Deprecated as of Mac OS X 10.6.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $resp_r

A reference to a scalar that can be used to contain the C<DTRefNum>
returned from the server.

=back

Error replies:

=over

=item kFPParamErr

Session reference number or Volume ID was invalid.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPOpenDT { # {{{1
    my($self, $VolumeID, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxn', kFPOpenDT, $VolumeID), \$resp);
    return $rc unless $rc == kFPNoErr;
    (${$resp_r}) = unpack('n', $resp);
    return $rc;
} # }}}1

=item FPOpenFork()

Opens a fork of an existing file for reading or writing.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item Flag

Bit 7 of the Flag parameter is the ResourceDataFlag bit, and
it indicates which fork to open, where 0 specifies the data
fork and 1 specifies the resource fork.

=item VolumeID

Volume ID.

=item DirectoryID

Ancestor Directory ID.

=item Bitmap

Bitmap describing the fork parameters to be returned. Set the bit that
corresponds to each desired parameter. This bitmap is the same as the
C<FileBitmap> parameter of the L</FPGetFileDirParms> command and can
be null. For bit definitions for the File bitmap, see
L<Net::AFP::FileParms>.

=item AccessMode

Desired access and deny modes, specified by any combination of the
following bits:

 0 = Read - allows the fork to be read
 1 = Write - allows the fork to be written
 4 = DenyRead - prevents others from reading the fork while it is open
 5 = DenyWrite - prevents others from writing the fork while it is open

For more information on access and deny modes, see L</"File Sharing Modes">.

=item PathType

Type of names in C<Pathname>. See L</"Path Type Constants"> for
possible values.

=item Pathname

Pathname to the desired file (cannot be null).

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code, followed by key-value pairs containing
information returned from the server about the opened fork.

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required
to open the specified fork.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that
cannot be obtained with this command (the fork is
not opened).

=item kFPDenyConflict

File or fork cannot be opened because of a deny
modes conflict.

=item kFPMiscErr

A non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file.

=item kFPObjectLocked

Attempt was made to open a file for writing that
is marked WriteInhibit.

=item kFPObjectTypeErr

Input parameters point to a directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname
type is unknown; a pathname is invalid.

=item kFPTooManyFilesOpen

Server cannot open another fork.

=item kFPVolLocked

Attempt was made to open for writing a file on a
volume that is marked ReadOnly.

=back

=cut
sub FPOpenFork { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flag'} ||= 0;
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    croak('AccessMode must be provided')
            unless exists $options{'AccessMode'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CCnNnna*', kFPOpenFork,
            @options{'Flag', 'VolumeID', 'DirectoryID', 'Bitmap', 'AccessMode'},
            PackagePath(@options{'PathType', 'Pathname'}));

    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    croak('Need to accept returned list') unless wantarray();
    if ($rc == kFPNoErr) {
        my ($rBitmap, $OForkRefNum, $FileParameters) = unpack('nna*', $resp);
        %rvals = %{ _ParseFileParms($rBitmap, $FileParameters) };
        $rvals{'OForkRefNum'} = $OForkRefNum;
    }
    return($rc, %rvals);
} # }}}1

=item FPOpenVol()

Opens a volume.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Bitmap

Bitmap describing the parameters that are to be returned. Set the bit that
corresponds to each desired parameter. The bitmap is the same as the Volume
bitmap used by the L</FPGetVolParms> command and cannot be null. For bit
definitions, see L<Net::AFP::VolParms>.

=item $VolumeName

Name of the volume as returned by L</FPGetSrvrParms>.

=item $Password

Optional volume password.

=item $resp_r

A reference to a scalar that can be used to return
a reference to a hash containing information about
the server.

=back

Error replies:

=over

=item kFPAccessDenied

Password was not supplied or does not match.

=item kFPBitmapErr

Attempt was made to retrieve a parameter that cannot
be retrieved with this command. (The bitmap is null.)

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing volume.

=item kFPParamErr

Session reference number or volume name is unknown.

=back

=cut
sub FPOpenVol { # {{{1
    my ($self, $Bitmap, $VolumeName, $Password, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';
    
    # If the caller passed undef, just set an empty bitmap.
    $Bitmap ||= 0;

    # Make sure the VolID bit is set, because it's kind of necessary.
    $Bitmap |= kFPVolIDBit;

    my $PackPattern = 'CxnCa*';
    my @PackArgs = (kFPOpenVol, $Bitmap, length($VolumeName), $VolumeName);
    # Only append a password if one was provided. If not, we don't provide
    # it.
    if (defined $Password) {
        $PackPattern .= 'x![s]Z8';
        push(@PackArgs, $Password);
    }
    my $msg = pack($PackPattern, @PackArgs);

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc unless $rc == kFPNoErr;
    ${$resp_r} = _ParseVolParms($resp);
    return $rc;
} # }}}1

=item FPRead()

Reads a block of data.

Deprecated; use C<FPReadExt()> instead.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item OForkRefNum

Open fork reference number.

=item Offset

Number of the first byte to read.

=item ReqCount

Number of bytes to read.

=item NewLineMask

Mask for determining where the read should terminate.

=item NewLineChar

Character for determining where the read should terminate.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code and a string containing the data read from the
referenced fork.

Error replies:

=over

=item kFPAccessDenied

Fork was not opened for read access.

=item kFPEOFErr

End of fork was reached. (This will be returned if
the end of the fork is reached at any point during
the read. Any data read will be returned.)

=item kFPLockErr

Some or all of the requested range is locked by
another user. (This will be returned if the read is
partially obscured by a locked range. Any data read
will be returned.)

=item kFPMiscErr

A non-AFP error occurred.

=item kFPParamErr

Session reference number or open fork reference number
is unknown; ReqCount or Offset is negative; NewLineMask
is invalid.

=back

=cut
sub FPRead { # {{{1
    my($self, %options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('ReqCount must be provided')
            unless exists $options{'ReqCount'};
    $options{'NewLineMask'} ||= 0;
    $options{'NewLineChar'} ||= 0;

    my $msg = pack('CxnNNCC', kFPRead,
            @options{'OForkRefNum', 'Offset', 'ReqCount', 'NewLineMask',
                     'NewLineChar'});

    croak('Need to accept returned list') unless wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

=item FPReadExt()

Reads a block of data.

Arguments:

Arguments are passed as key-value pair for this method.

=over

=item OForkRefNum

Open fork reference number.

=item Offset

Number of the first byte to read.

=item ReqCount

Number of bytes to read.

=item $resp_r

A reference to a scalar which will contain the data read from the
referenced fork.

=back

Returns:

A scalar indicating the error code from the call. Upon success, a list
containing the error code and a string containing the data read from the
referenced fork.

Error replies:

=over

=item kFPAccessDenied

Fork was not opened for read access.

=item kFPEOFErr

End of fork was reached. (This will be returned if the end of the fork
is reached at any point during the read. Any data read will be returned.)

=item kFPLockErr

Some or all of the requested range is locked by another user. (This
will be returned if the read is partially obscured by a locked range.
Any data read will be returned.)

=item kFPMiscErr

A non-AFP error occurred.

=item kFPParamErr

Session reference number or open fork reference number is unknown;
ReqCount or Offset is negative; NewLineMask is invalid.

=back

=cut
sub FPReadExt { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('ReqCount must be provided')
            unless exists $options{'ReqCount'};
    
    my $msg = pack('CxnNNNN', kFPReadExt, $options{'OForkRefNum'},
            ll_convert($options{'Offset'}), ll_convert($options{'ReqCount'}));

    croak('Need to accept returned list') unless wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

=item FPRemoveAPPL()

Removes an APPL mapping from a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $DTRefNum

Desktop database reference number.

=item $DirectoryID

Directory ID.

=item $FileCreator

File creator of the application corresponding to the APPL mapping that
is to be removed.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname to desired file or directory.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPItemNotFound

No APPL mapping corresponding to the input parameters was found in the
Desktop database.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file.

=item kFPParamErr

Session reference or Desktop database reference number is unknown.

=back

=cut
sub FPRemoveAPPL {
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('DTRefNum must be provided')
            unless exists $options{'DTRefNum'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('FileCreator must be provided')
            unless exists $options{'FileCreator'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNNa*', kFPRemoveAPPL,
            @options{'DTRefNum', 'DirectoryID', 'FileCreator'},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
}

=item FPRemoveComment()

Removes a comment from a volume's Desktop database.

Deprecated as of Mac OS X 10.6.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $DTRefNum

Desktop database reference number.

=item $DirectoryID

Directory ID.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname to desired file or directory.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPItemNotFound

Comment was not found in the Desktop database.

=item kFPParamErr

Session reference number, Desktop database reference number, or
pathname type is unknown; pathname is invalid.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=back

=cut
sub FPRemoveComment { # {{{1
    my($self, $DTRefNum, $DirectoryID, $PathType, $Pathname) = @_;
    DEBUG('called ', (caller(0))[3]);

    my $msg = pack('CxnNa*', kFPRemoveComment, $DTRefNum, $DirectoryID,
            PackagePath($PathType, $Pathname));
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPRemoveExtAttr()

Removes an extended attribute.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume identifier.

=item $DirectoryID

Directory identifier.

=item $Bitmap

Bitmap specifying the desired behavior when removing an extended attribute.
For this command, C<kAttrDontFollow> is the only valid bit. For details,
see L<Net::AFP::ExtAttrs/"Extended Attributes Bitmap">.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname to desired file or directory.

=item $Name

UTF-8 encoded name of the extended attribute that is to be removed.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to remove an extended
attribute for the specified file or directory.

=item kFPBitmapErr

Bitmap is null or specifies a value that is invalid for this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPRemoveExtAttr { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('Name must be provided')
            unless exists $options{'Name'};

    my $msg = pack('CxnNna*x![s]n/a*', kFPRemoveExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{'Name'})));
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPRename()

Renames a file or directory.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Ancestor Directory ID.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for possible values.

=item $Pathname

Pathname to the CNode whose name is being changed (cannot be null).

=item $NewType

Type of names in C<$NewName>. See L</"Path Type Constants"> for possible values.

=item $NewName

Pathname to the CNode, including its new name (cannot be null).

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPCantRename

Attempt was made to rename a volume or root directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectExists

File or directory having the name specified by C<$NewName> already exists.

=item kFPObjectLocked

File or directory is marked RenameInhibit.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown; pathname or C<$NewName> is invalid.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPRename { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('NewType must be provided')
            unless exists $options{'NewType'};
    croak('NewName must be provided')
            unless exists $options{'NewName'};

    my $msg = pack('CxnNa*a*', kFPRename,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPResolveID()

Gets parameters for a file by File ID.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $FileID

File ID that is to be deleted.

=item $Bitmap

Bitmap describing the parameters to return. Set the bit that corresponds
to each desired parameter. This bitmap is the same as the C<$FileBitmap>
parameter of the L</FPGetFileDirParms> command. For bit definitions for
the this bitmap, see L<Net::AFP::FileParms/File Bitmap>.

=item $resp_r

A reference to a scalar which will contain a hash reference with the
requested file parameters.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBadIDErr

File ID is not valid.

=item kFPCallNotSupported

Server does not support this command.

=item kFPIDNotFound

File ID was not found. (No file thread exists.)

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectTypeErr

Object defined was a directory, not a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
pathname is null or bad.

=back

=cut
sub FPResolveID {
    my($self, $VolumeID, $FileID, $Bitmap, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $msg = pack('CxnNn', kFPResolveID, $VolumeID, $FileID, $Bitmap);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) unless $rc == kFPNoErr;
    my($Bitmap_n, $data) = unpack('na*', $resp);
    my $info = _ParseFileParms($Bitmap_n, $data);
    ${$resp_r} = {
                   'Bitmap'                 => $Bitmap_n,
                   'RequestedParameters'    => $info,
                 };
    return $rc;
}

=item FPSetACL()

Sets the UUID, Group UUID, and ACL for a file or directory, or removes the
ACL from a file or directory.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume identifier.

=item $DirectoryID

Directory identifier.

=item $Bitmap

Bits that specify the values that are to be set. Specify C<kFileSec_UUID>
to set the UUID of the specified file or directory. Specify
C<kFileSec_GRPUUID> to set the Group UUID of the specified file or
directory. Specify C<kFileSec_ACL> to set the ACL of the specified file
or directory or C<kFileSec_REMOVEACL> to remove the file or directory's
ACL. If sending this command is part of the creation of a new item, set
the C<kFileSec_Inherit> bit. When the server receives an L</FPSetACL>
command having a Bitmap parameter in which the C<kFileSec_Inherit> bit
is set, it scans the current item looking for access control entries
(ACEs) in which the C<KAUTH_ACE_INHERITED> bit is set in its C<ace_flags>
field. The server copies any currently inherited ACEs to the end of the
incoming list of ACEs and sets the ACL on the item. For declarations of
these constants, see L<Net::AFP::ACL/Access Control List Bitmap>.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname of the file or directory for which the access control list (ACL)
is to be obtained.

=item $AdditionalInformation

A hash reference containing additional parameters, based on the flags
passed in the C<$Bitmap> argument. If C<kFileSec_UUID> is set, the
C<UUID> key should contain the user UUID. If C<kFileSec_GRPUUID> is
set, the C<GRPUUID> key should contain the group UUID. If
C<kFileSec_ACL> is set, the C<acl_flags> and C<acl_ace> keys should
contain the corresponding information.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access rights required to get the ACL for the
specified file or directory.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPSetACL { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $msg = pack('CxnNna*x![s]', kFPSetACL,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}));
    if ($options{'Bitmap'} & kFileSec_UUID) {
        croak('UUID must be provided')
                unless exists $options{'UUID'};
        $msg .= uuid_pack($options{'UUID'});
    }
    if ($options{'Bitmap'} & kFileSec_GRPUUID) {
        croak('GRPUUID must be provided')
                unless exists $options{'GRPUUID'};
        $msg .= uuid_pack($options{'GRPUUID'});
    }
    if ($options{'Bitmap'} & kFileSec_ACL) {
        croak('acl_ace must be provided')
                unless exists $options{'acl_ace'};
        croak('acl_flags must be provided')
                unless exists $options{'acl_flags'};
        my @ace_list;
        foreach my $ace (@{$options{'acl_ace'}}) {
            push(@ace_list, pack('a[16]NN',
                    uuid_pack(${$ace}{'ace_applicable'}),
                    @{$ace}{'ace_flags', 'ace_rights'}));
        }
        $msg .= pack('NN(a*)[' . scalar(@ace_list) . ']', scalar(@ace_list),
            $options{'acl_flags'}, @ace_list);
    }
    
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPSetDirParms()

Sets parameters for a directory.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Ancestor Directory ID.

=item $Bitmap

Bitmap describing the parameters to set. Set the bit that corresponds to
each desired parameter. This bitmap is the same as the C<$DirectoryBitmap>
parameter of the L</FPGetFileDirParms> command. For bit defintions for
this bitmap, see L<Net::AFP::DirParms>.

=item $PathType

Type of name in C<$Pathname>. See L</"Path Type Constants"> for possible values.

=item $Pathname

Pathname to the desired directory.

=item %DirectoryParameters:

Parameters to be set, passed as a hash. Only the values C<Attribute>,
C<CreateDate>, C<ModDate>, C<BackupDate>, C<FinderInfo>, C<OwnerID>,
C<GroupID>, C<AccessRights>, C<UnixUID>, C<UnixGID>, C<UnixPerms>,
and C<UnixAccessRights> may be updated in this way.

If any of the Unix* parameters are passed, they must all be passed at
the same time, or C<kFPParamErr> will be returned.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to
use this command.

=item kFPBitmapErr

Attempt was made to set a parameter that cannot be
set by this command; bitmap is null.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing directory.

=item kFPObjectTypeErr

Input parameters point to a file.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown; pathname,
Owner ID or Group ID is invalid or not specified.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPSetDirParms { # {{{1
    my($self, %options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('Bitmap must be provided')
            unless exists $options{'Bitmap'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $Mask = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
               kFPBackupDateBit | kFPFinderInfoBit | kFPOwnerIDBit |
               kFPGroupIDBit | kFPAccessRightsBit | kFPUnixPrivsBit;
    if ($options{'Bitmap'} & (~$Mask & 0xFFFFFFFF)) {
        # attempting to set something which doesn't make sense for
        # FPSetDirParms...
        return kFPParamErr;
    }
    my $ParamsBlock = PackSetParams($options{'Bitmap'}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', kFPSetDirParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPSetExtAttr()

Sets the value of an extended attribute.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume identifier.

=item $DirectoryID

Directory identifier.

=item $Bitmap

Bitmap specifying the desired behavior when setting the value of an
extended attribute. For details, see
L<Net::AFP::ExtAttrs/"Extended Attributes Bitmap">.

=item $Offset

Always zero; reserved for future use.

=item $PathType

Type of names in C<$Pathname>. See L</"Path Type Constants"> for
possible values.

=item $Pathname

Pathname to desired file or directory.

=item $Name

UTF-8 encoded name of the extended attribute whose value is to be set.

=item $AttributeData

Value to which the extended attribute is to be set.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to set an extended
attribute for the specified file or directory.

=item kFPBitmapErr

Bitmap is null or specifies a value that is invalid for this command.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

A parameter is invalid.

=back

=cut
sub FPSetExtAttr { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    $options{'Bitmap'} ||= 0;
    $options{'Offset'} ||= 0;
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};
    croak('Name must be provided')
            unless exists $options{'Name'};
    croak('AttributeData must be provided')
            unless exists $options{'AttributeData'};

    my $msg = pack('CxnNnNNa*x![s]n/a*N/a*', kFPSetExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            ll_convert($options{'Offset'}),
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{'Name'})),
            $options{'AttributeData'});
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPSetFileDirParms()

Sets parameters for a file or a directory.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Ancestor Directory ID.

=item $Bitmap

Bitmap describing the parameters to set. Set the bit that corresponds to
each desired parameter. This bitmap can be the same as the C<$DirectoryBitmap>
or the C<$FileBitmap> parameter of the L</FPGetFileDirParms> command, but
this command can only set the parameters common to both bitmaps. For bit
definitions for the Directory bitmap, see L<Net::AFP::DirParms>; for bit
definitions for the File bitmap, see L<Net::AFP::FileParms>.

=item $PathType

Type of name in C<$Pathname>. See L</"Path Type Constants"> for possible values.

=item $Pathname

Pathname to the desired file or directory.

=item %DirectoryParameters

Parameters to be set, passed as a hash. Only the values C<Attribute>,
C<CreateDate>, C<ModDate>, C<BackupDate>, C<FinderInfo>, C<UnixUID>,
C<UnixGID>, C<UnixPerms>, and C<UnixAccessRights> may be updated in
this way.

If any of the Unix* parameters are passed, they must all be passed at
the same time, or C<kFPParamErr> will be returned.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to set a parameter that cannot be set by this command;
bitmap is null.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file or directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
C<$Pathname> is invalid.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPSetFileDirParms { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('Bitmap must be provided')
            unless exists $options{'Bitmap'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $Mask = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
               kFPBackupDateBit | kFPFinderInfoBit | kFPUnixPrivsBit;
    if ($options{'Bitmap'} & (~$Mask & 0xFFFFFFFF)) {
        # attempting to set something which doesn't make sense for
        # FPSetFileDirParms...
        return kFPParamErr;
    }
    my $ParamsBlock = PackSetParams($options{'Bitmap'}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', kFPSetFileDirParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPSetFileParms()

Sets parameters for a file.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $DirectoryID

Ancestor Directory ID.

=item $Bitmap

Bitmap describing the parameters to set. Set the bit that corresponds to
each desired parameter. This bitmap can be the same as the C<$FileBitmap>
parameter of the L</FPGetFileDirParms> command. For bit definitions for
the File bitmap, see L<Net::AFP::FileParms>.

=item $PathType

Type of name in C<$Pathname>. See L</"Path Type Constants"> for possible values.

=item $Pathname

Pathname to the desired file or directory.

=item %DirectoryParameters

Parameters to be set, passed as a hash. Only the values C<Attribute>,
C<CreateDate>, C<ModDate>, C<BackupDate>, C<FinderInfo>, C<UnixUID>,
C<UnixGID>, C<UnixPerms>, and C<UnixAccessRights> may be updated in
this way.

If any of the Unix* parameters are passed, they must all be passed at
the same time, or C<kFPParamErr> will be returned.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required to use this command.

=item kFPBitmapErr

Attempt was made to set a parameter that cannot be set by this command;
bitmap is null.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPObjectNotFound

Input parameters do not point to an existing file.

=item kFPObjectTypeErr

Input parameters point to a directory.

=item kFPParamErr

Session reference number, Volume ID, or pathname type is unknown;
C<$Pathname> is invalid.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPSetFileParms { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('DirectoryID must be provided')
            unless exists $options{'DirectoryID'};
    croak('Bitmap must be provided')
            unless exists $options{'Bitmap'};
    croak('PathType must be provided')
            unless exists $options{'PathType'};
    croak('Pathname must be provided')
            unless exists $options{'Pathname'};

    my $Mask = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
               kFPBackupDateBit | kFPFinderInfoBit | kFPLaunchLimitBit |
               kFPUnixPrivsBit;
    if ($options{'Bitmap'} & (~$Mask & 0xFFFFFFFF)) {
        # attempting to set something which doesn't make sense for
        # FPSetFileParms...
        return kFPParamErr;
    }
    my $ParamsBlock = PackSetParams($options{'Bitmap'}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', kFPSetFileParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg);
} # }}}1

=item FPSetForkParms()

Sets the length of a fork.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $OForkRefNum

Open fork reference number.

=item $Bitmap

Bitmap describing the parameters to be set. Set the bit that corresponds
to each desired parameter. This bitmap is the same as the C<$FileBitmap>
of the L</FPGetFileDirParms> command, but only the Data Fork Length,
Resource Fork Length, Extended Data Fork Length, and Extended Resource
Fork Length parameters can be set. For bit definitions for this bitmap,
see L<Net::AFP::FileParms>.

=item $ForkLen

New end-of-fork value.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required
to use this command.

=item kFPBitmapErr

Attempt was made to set a parameter that cannot be
set by this command; bitmap is null.

=item kFPDiskFull

No more space exists on the volume.

=item kFPLockErr

Range lock conflict exists.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference number or fork reference number
is invalid.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPSetForkParms { # {{{1
    my ($self, $OForkRefNum, $Bitmap, $ForkLen) = @_;
    DEBUG('called ', (caller(0))[3]);

    my $packed = undef;
    if (($Bitmap & kFPDataForkLenBit) or
        ($Bitmap & kFPRsrcForkLenBit)) {
        $packed = pack('N', $ForkLen);
    }
    elsif (($Bitmap & kFPExtDataForkLenBit) or
             ($Bitmap & kFPExtRsrcForkLenBit)) {
        $packed = pack('NN', ll_convert($ForkLen));
    }

    return $self->SendAFPMessage(pack('Cxnna*', kFPSetForkParms, $OForkRefNum,
            $Bitmap, $packed));
} # }}}1

=item FPSetVolParms()

Set a volume's backup date.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume ID.

=item $Bitmap

Bitmap describing the parameters to be set. This parameter is the same
as the C<$Bitmap> parameter for the L</FPGetVolParms> command, but only
the Backup Date bit can be set. For bit definitions for this bitmap,
see L<Net::AFP::VolParms>.

=item $BackupDate

New backup date.

=back

Error replies:

=over

=item kFPAccessDenied

User does not have the access privileges required
to use this command.

=item kFPBitmapErr

Attempt was made to set a parameter that cannot be
set by this command; bitmap is null.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference number or Volume ID is unknown.

=item kFPVolLocked

Volume is ReadOnly.

=back

=cut
sub FPSetVolParms { # {{{1
    my ($self, $VolumeID, $Bitmap, $BackupDate) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxnnN', kFPSetVolParms, $VolumeID,
            $Bitmap, $BackupDate));
} # }}}1

=item FPSyncDir()

Synchronize changes to a directory out to physical storage.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $VolumeID

Volume identifier.

=item $DirectoryID

Directory identifier.

=back

Error replies:

=over

=back

=cut
sub FPSyncDir { # {{{1
    my($self, $VolumeID, $DirectoryID) = @_;
    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN', kFPSyncDir, $VolumeID,
            $DirectoryID));
} # }}}1

=item FPSyncFork()

Synchronize writes to an open file out to physical storage.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $OForkRefNum

Open fork reference number.

=back

Error replies:

=over

=back

=cut
# AFP command 79 is for FPSyncFork. You get this, as you worked out, by calling fcntl F_FULLFSYNC on a file. The command layout is:
#  byte CommandCode
#  byte Pad
#  short OForkRefNum
sub FPSyncFork { # {{{1
    my($self, $OForkRefNum) = @_;
    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPSyncFork, $OForkRefNum));
} # }}}1

=item FPWrite()

Write a block of data to an open fork.

Deprecated; use C<FPWriteExt()> instead.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Flag

Bit 7 is the C<StartEndFlag> bit, and indicates whether C<$Offset> is
relative to the beginning or end of the fork. A value of zero indicates
that the start is relative to the beginning of the fork; a value of 1
indicates that the start is relative to the end of the fork.

=item $OForkRefNum

Open fork reference number.

=item $Offset

Byte offset from the beginning or the end of the fork indicating where
the write is to begin; a negative value indicates a byte within the
fork relative to the end of the fork.

=item $ReqCount

Number of bytes to be written.

=item $ForkData

A reference to a scalar containing data to be written, which is not part
of the request block. Instead, the data is transmitted to the server in
an intermediate exchange of DSI packets.

=item $resp_r

A reference to a scalar which will contain a hash
containing returned values from the server call.

=back

Error replies:

=over

=item kFPAccessDenied

Fork is not open for writing by this user.

=item kFPDiskFull

No space exists on this volume.

=item kFPLockErr

Some or all of the requested range is locked by another user.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference numer or open fork reference number is unknown.

=back

=cut
sub FPWrite { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flag'} ||= 0;
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('ForkData must be provided')
            unless exists $options{'ForkData'};
    $options{'ReqCount'} ||= length(${$options{'ForkData'}});

    my $msg = pack('CCnNN', kFPWrite,
            @options{'Flag', 'OForkRefNum', 'Offset', 'ReqCount'});

    my $resp;
    my $rc = $self->SendAFPWrite($msg, @options{'ForkData', 'ReqCount'},
            \$resp);
    if ($rc == kFPNoErr && wantarray()) {
        return($rc, unpack('N', $resp));
    }
    return($rc);
} # }}}1

=item FPWriteExt()

Writes a block of data to an open fork.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Flag

Bit 7 is the C<StartEndFlag> bit, and indicates whether C<$Offset> is
relative to the beginning or end of the fork. A value of zero indicates
that the start is relative to the beginning of the fork; a value of 1
indicates that the start is relative to the end of the fork.

=item $OForkRefNum

Open fork reference number.

=item $Offset

Byte offset from the beginning or the end of the fork indicating where
the write is to begin; a negative value indicates a byte within the
fork relative to the end of the fork.

=item $ReqCount

Number of bytes to be written.

=item $ForkData_r

A reference to a scalar containing data to be written, which is not part of
the request block. Instead, the data is transmitted to the server in an
intermediate exchange of DSI packets.

=item $resp_r

A reference to a scalar which will contain a hash
containing returned values from the server call.

=back

Error replies:

=over

=item kFPAccessDenied

Fork is not open for writing by this user.

=item kFPDiskFull

No space exists on this volume.

=item kFPLockErr

Some or all of the requested range is locked by another user.

=item kFPMiscErr

Non-AFP error occurred.

=item kFPParamErr

Session reference numer or open fork reference number is unknown.

=back

=cut
sub FPWriteExt { # {{{1
    my($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    $options{'Flag'} ||= 0;
    croak('OForkRefNum must be provided')
            unless exists $options{'OForkRefNum'};
    croak('Offset must be provided')
            unless exists $options{'Offset'};
    croak('ForkData must be provided')
            unless exists $options{'ForkData'};
    $options{'ReqCount'} ||= length(${$options{'ForkData'}});

    my $msg = pack('CCnNNNN', kFPWriteExt, @options{'Flag', 'OForkRefNum'},
            ll_convert($options{'Offset'}), ll_convert($options{'ReqCount'}));

    my $resp;
    my $rc = $self->SendAFPWrite($msg, @options{'ForkData', 'ReqCount'},
            \$resp);
    if ($rc == kFPNoErr && wantarray()) {
        return($rc, ll_unconvert(unpack('NN', $resp)));
    }
    return $rc;
} # }}}1

=item FPZzzzz()

Notifies the server that the client is going to sleep.

Arguments:

=over

=item $self

An object that is a subclass of Net::AFP.

=item $Flags

Reserved.

=back

Error replies:

None.

=cut
sub FPZzzzz { # {{{1
    my ($self, $Flags) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxN', kFPZzzzz, $Flags));
} # }}}1

=back

=head1 REFERENCES

The Apple Filing Protocol implementation contained herein is based on the
protocol description as provided by Apple, in their online documentation.
The HTML version of the conceptual documentation is available at:

L<http://developer.apple.com/mac/library/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html>

and the PDF version is available at:

L<http://developer.apple.com/documentation/Networking/Conceptual/AFP/AFP3_1.pdf>

The reference for the actual AFP protocol operations, arguments and other
information is available in HTML form at:

L<http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/Reference/reference.html>

and the PDF version is available at:

L<http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/AFP_Reference.pdf>

=head1 DEVELOPER NOTES

Notes related to netatalk:

- Netatalk sends its own DSICloseSession request packet to the client.
This is not in keeping with the AFP and DSI protocol specs; the
DSICloseSession packet from the server gets dropped because the
FIN/ACK has already been sent by that time. It doesn't appear to
bother the code, but it's weird.

- Upon FPLogout, netatalk will send a DSICloseSession to the client
and terminate the connection. Worked around easily, but still pretty
goofy.

- Also, Netatalk will in certain cases return a positive (undefined)
error code; it uses the received data structure to assemble its
reply, and the error code field is the same field that contains the
data offset pointer. I've implemented a hack in Net::DSI::Session (in the
thread main loop) to work around this.

- Discovered that Netatalk's DSI implementation doesn't like getting
Tickle packets before the session has been opened; made a little
workaround for that.

Notes on AFP:

- Apple's documentation of the FPChangePassword method indicates that
no response block will be returned; in the case of anything more
complicated than the Plaintext UAM, this is categorically wrong. Most
UAMs need to perform two-way conversations for their password change
operations.

- Apple's documentation of the FPLogin operation is wrong. Their docs
indicate a pad byte after the command code byte. I have verified
empirically that no server implementation does this.

- Apple's documentation of the FPLoginCont operation indicates that the
UserAuthInfo block will only be present if kFPAuthContinue is returned;
the 2-way randnum UAM returns kFPNoErr and a UserAuthInfo block in the
last stage of its authentication path.

- Apple's documentation of the FPMapID and FPMapName operations was
not properly updated in AFP 3.1 and 3.2 to cover the sending/receiving of
UUIDs. The AFP 3.3 documentation does, but butchers the data type - a
UUID is 128 bits, not 64, so a "uint64_t" isn't possibly large enough.
Getting it as a 16-byte string instead, which works for us fine.

- Apple's documentation of the FPSetACL operation provides a visual
representation of the data layout in the kFPSetACL message. It claims
there is a MaxReplySize field between the Bitmap and PathType fields.
No such fields is present (verified empirically).

- Apple's documentation of the FPSetForkParms operation indicates that
the data field is only 4 bytes, while it also claims that it can be used
to set the extended resource and data fork lengths. Code was altered to
pass a 'long long' in the message payload when the extended params are
to be set.

- Apple's documentation for the FPWrite operation indicates it returns
the number of bytes written. It does not, and has never done this;
however, it does return an integer value (32 bits for FPWrite, 64
bits for FPWriteExt) indicating the offset after the last write request.

- It seems that Apple (as of the AFP implementation contained in their
AirDisk devices, i.e., the Airport Express 802.11n Dualband) either forgot
about or changed their minds about write-only files via AFP. Opening
a fork with the "write-only" flag, and then attempting to write to that
open handle, yields failed writes. Opening the file as read-write in
that case allows successful writes.

=head1 DEPENDENCIES

C<Log::Log4perl> for message handling. Most other dependencies are
endemic to the top-level modules that implement the specific transport
layers, C<Net::AFP::TCP> and C<Net::AFP::Atalk>.

=head1 BUGS AND LIMITATIONS

Don't know of any bugs yet, but they're probably in there...

My unicode handling is probably imperfect; some Korean scripts probably
aren't handled right, along with certain characters that Mac OS prefers
be composed instead of uncomposed (but most have to be uncomposed)...

Also need to handle disconnections better.

No clue how/if this will work with Fuse on Solaris. Theoretically should
work...

Unimplemented functions:

- FPCatSearch{,Ext}

=head1 INCOMPATIBILITIES

None known; should work with all Perl modules and AFP server implementations
(I've tested with netatalk, MacOS 9, OS X, Apple's AirDisk, and Jaffer
to date).

=head1 AUTHOR

Derrik Pates <demon@devrandom.net>.

=head1 SEE ALSO

C<Net::AFP::TCP>, C<Net::AFP::Atalk>

=cut
1;
# vim: ts=4 fdm=marker
