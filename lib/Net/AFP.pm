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
use Net::AFP::Versions;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Exporter qw(import);
use Log::Log4perl qw(:easy);
use Carp;
# }}}1

our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
                 kFPHardCreate kFPStartEndFlag kFPLockUnlockFlag);

# define constants {{{1
our $VERSION = '0.69.0';
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
use constant kFPGetAuthMethods          => 62;  # AFP 3.0
use constant kFPLoginExt                => 63;  # AFP 3.0
use constant kFPGetSessionToken         => 64;  # AFP 3.0
use constant kFPDisconnectOldSession    => 65;  # AFP 3.0
use constant kFPEnumerateExt            => 66;  # AFP 3.0
use constant kFPCatSearchExt            => 67;  # AFP 3.0
use constant kFPEnumerateExt2           => 68;  # AFP 3.1
use constant kFPGetExtAttr              => 69;  # AFP 3.2
use constant kFPSetExtAttr              => 70;  # AFP 3.2
use constant kFPRemoveExtAttr           => 71;  # AFP 3.2
use constant kFPListExtAttrs            => 72;  # AFP 3.2
use constant kFPGetACL                  => 73;  # AFP 3.2
use constant kFPSetACL                  => 74;  # AFP 3.2
use constant kFPAccess                  => 75;  # AFP 3.2
use constant kFPSpotlightRPC            => 76;  # AFP 3.2+ (10.5)
use constant kFPSyncDir                 => 78;  # AFP 3.2+ (10.5)
use constant kFPSyncFork                => 79;  # AFP 3.2+ (10.5)
use constant kFPZzzzz                   => 122; # AFP 2.3
use constant kFPAddIcon                 => 192; # AFP 2.0
# }}}1

use constant kFPShortName       => 1;
use constant kFPLongName        => 2;
use constant kFPUTF8Name        => 3;   # AFP 3.0

use constant kFPSoftCreate      => 0;
use constant kFPHardCreate      => 0x80;

use constant kFPStartEndFlag    => 0x80;
use constant kFPLockUnlockFlag  => 1;

# This class is only to be inherited. It uses virtual methods to talk to
# the server by whatever protocol the inheriting class is supposed to
# talk over, so we want this to be as generic as possible.
sub new { # {{{1
    my ($class, $host, $port) = @_;
    DEBUG('called ', (caller(0))[3]);
    my $obj = {};
    bless $obj, $class;
    my $logparms = <<'_EOT_';
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

sub FPAddAPPL { # {{{1
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
} # }}}1

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

sub FPAddIcon { # {{{1
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
} # }}}1

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
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') unless wantarray();
        return($rc, unpack('N', $resp));
    }
    return $rc;
} # }}}1

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

    my $msg = pack('CCnNNNN', kFPByteRangeLockExt,
            @options{'Flags', 'OForkRefNum'},
            ll_convert($options{'Offset'}),
            ll_convert($options{'Length'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') unless wantarray();
        return($rc, ll_unconvert(unpack('NN', $resp)));
    }
    return $rc;
} # }}}1

sub FPCatSearch {
    my ($self, %options) = @_;

    DEBUG('called ', (caller(0))[3]);
    ERROR('called function ', (caller(0))[3], ' not implemented');
    croak('Not yet implemented');
    croak('VolumeID must be provided')
            unless exists $options{'VolumeID'};
    croak('ReqMatches must be provided')
            unless exists $options{'ReqMatches'};
    $options{'CatalogPosition'} ||= '';
    $options{'FileRsltBitmap'} ||= 0;
    $options{'DirectoryRsltBitmap'} ||= 0;
    $options{'ReqBitmap'} ||=

    my $msg = pack('CxnNx[4]a[16]nnN', kFPCatSearch,
            @options{'VolumeID', 'ReqMatches', 'CatalogPosition',
                     'FileRsltBitmap', 'DirectoryRsltBitmap',
                     'ReqBitmap'});
}

sub FPCatSearchExt {
    DEBUG('called ', (caller(0))[3]);
    ERROR('called function ', (caller(0))[3], ' not implemented');
    croak('Not yet implemented');
}

sub FPChangePassword { # {{{1
    my ($self, $UAM, $UserName, $UserAuthInfo, $resp_r) = @_;
    DEBUG('called ', (caller(0))[3]);

    if (ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF') {
        $resp_r = \q//;
    }

    $UserAuthInfo ||= q//;

    my $msg = pack('CxC/a*x![s]C/a*x![s]a*', kFPChangePassword, $UAM,
            $UserName, $UserAuthInfo);
    return $self->SendAFPMessage($msg, $resp_r, 1);
} # }}}1

sub FPCloseDir { # {{{1
    my ($self, $VolumeID, $DirectoryID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN', kFPCloseDir, $VolumeID,
            $DirectoryID));
} # }}}1

sub FPCloseDT { # {{{1
    my($self, $DTRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseDT, $DTRefNum));
} # }}}1

sub FPCloseFork { # {{{1
    my($self, $OForkRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPCloseVol { # {{{1
    my ($self, $VolumeID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPCloseVol, $VolumeID), undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
            PackagePath(@options{'PathType', 'Pathname'})), \$resp, 1);
    return($rc, unpack('N', $resp))
            if $rc == kFPNoErr and wantarray();
    return $rc;
} # }}}1

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
            PackagePath(@options{'PathType', 'Pathname'})), undef, 1);
} # }}}1

sub FPCreateID { # {{{1
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
} # }}}1

sub FPDelete { # {{{1
    my($self, $VolumeID, $DirectoryID, $PathType, $Pathname) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnNa*', kFPDelete, $VolumeID,
            $DirectoryID, PackagePath($PathType, $Pathname)), undef, 1);
} # }}}1

sub FPDeleteID { # {{{1
    my($self, $VolumeID, $FileID) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxnN', kFPDeleteID, $VolumeID, $FileID));
} # }}}1

sub FPDisconnectOldSession { # {{{1
    my($self, $Type, $Token) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN/a', kFPDisconnectOldSession, $Type,
            $Token));
} # }}}1

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
    croak('Must accept array return') unless wantarray();

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
    return($rc, [@results]);
} # }}}1

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
    croak('Must accept array return') unless wantarray();

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
    return($rc, [@results]);
} # }}}1

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
    croak('Must accept array return') unless wantarray();

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
    return($rc, [@results]);
} # }}}1

sub FPExchangeFiles { # {{{1
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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPFlush { # {{{1
    my ($self, $VolumeID) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPFlush, $VolumeID), undef, 1);
} # }}}1

sub FPFlushFork { # {{{1
    my ($self, $OForkRefNum) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPFlushFork, $OForkRefNum),
            undef, 1);
} # }}}1

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

sub FPGetAPPL { # {{{1
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
} # }}}1

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

sub FPGetIcon { # {{{1
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
} # }}}1

sub FPGetIconInfo { # {{{1
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
} # }}}1

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
        ${$resp_r}->{'UserID'} = unpack('x[' . $offset . ']N', $resp);
        $offset += 4;
    }
    if ($rbmp & 0x2) {
        if (Net::AFP::Versions::CompareByVersionNum($self, 2, 1,
                kFPVerAtLeast)) {
            if (exists ${$resp_r}->{'UserID'}) {
                ${$resp_r}->{'PrimaryGroupID'} = ${$resp_r}->{'UserID'};
            }
        }
        else {
            ${$resp_r}->{'PrimaryGroupID'} =
                    unpack('x[' . $offset . ']N', $resp);
            $offset += 4;
        }
    }
    if ($rbmp & 0x4) {
        ${$resp_r}->{'UUID'} = uuid_unpack(unpack('x['.$offset.']a[16]', $resp));
        $offset += 16;
    }

    return $rc;
} # }}}1

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

sub FPLogout { # {{{1
    my ($self) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cx', kFPLogout));
} # }}}1

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
        ${${$resp_r}}{'UTF8Name'} =
                compose(decode_utf8(${${$resp_r}}{'UTF8Name'}));
    }
    elsif ($Subfunction == kUserIDToUTF8Name ||
            $Subfunction == kGroupIDToUTF8Name) {
        (${$resp_r}) = compose(decode_utf8(unpack('C/a', $resp)));
    }
    else {
        (${$resp_r}) = decode('MacRoman', unpack('C/a', $resp));
    }
    return $rc;
} # }}}1

sub FPMapName { # {{{1
    my($self, $Subfunction, $Name, $resp_r) = @_;

    DEBUG('called ', (caller(0))[3]);
    croak('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my $resp;
    my $pack_mask = 'CC';
    if ($Subfunction == kUTF8NameToUserUUID ||
            $Subfunction == kUTF8NameToGroupUUID) {
        $pack_mask .= 'n/a*';
        $Name = encode_utf8(decompose($Name));
    }
    else {
        $pack_mask .= 'C/a*';
        if ($Subfunction == kUTF8NameToUserID ||
                $Subfunction == kUTF8NameToGroupID) {
            $Name = encode_utf8(decompose($Name));
        }
        else {
            $Name = encode('MacRoman', $Name);
        }
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
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc;
} # }}}1

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
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    croak('Need to accept returned list') unless wantarray();
    if ($rc == kFPNoErr) {
        my ($rBitmap, $OForkRefNum, $FileParameters) = unpack('nna*', $resp);
        %rvals = %{ _ParseFileParms($rBitmap, $FileParameters) };
        $rvals{'OForkRefNum'} = $OForkRefNum;
    }
    return($rc, %rvals);
} # }}}1

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
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc unless $rc == kFPNoErr;
    ${$resp_r} = _ParseVolParms($resp);
    return $rc;
} # }}}1

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

sub FPRemoveAPPL { # {{{1
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
} # }}}1

sub FPRemoveComment { # {{{1
    my($self, $DTRefNum, $DirectoryID, $PathType, $Pathname) = @_;
    DEBUG('called ', (caller(0))[3]);

    my $msg = pack('CxnNa*', kFPRemoveComment, $DTRefNum, $DirectoryID,
            PackagePath($PathType, $Pathname));
    return $self->SendAFPMessage($msg);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPResolveID { # {{{1
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
} # }}}1

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
    
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

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
            $Bitmap, $packed), undef, 1);
} # }}}1

sub FPSetVolParms { # {{{1
    my ($self, $VolumeID, $Bitmap, $BackupDate) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxnnN', kFPSetVolParms, $VolumeID,
            $Bitmap, $BackupDate), undef, 1);
} # }}}1

sub FPSyncDir { # {{{1
    my($self, $VolumeID, $DirectoryID) = @_;
    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('CxnN', kFPSyncDir, $VolumeID,
            $DirectoryID), undef, 1);
} # }}}1

sub FPSyncFork { # {{{1
    my($self, $OForkRefNum) = @_;
    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cxn', kFPSyncFork, $OForkRefNum),
            undef, 1);
} # }}}1

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

sub FPZzzzz { # {{{1
    my ($self, $Flags) = @_;

    DEBUG('called ', (caller(0))[3]);
    return $self->SendAFPMessage(pack('CxN', kFPZzzzz, $Flags));
} # }}}1

1;
# vim: ts=4 fdm=marker
