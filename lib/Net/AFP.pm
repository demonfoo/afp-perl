# $HeadURL$
# $Revision$
# $Date$

# imports {{{1
package Net::AFP;
use strict;
use warnings;
use diagnostics;
use integer;
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
use Params::Validate qw(:all);
use Carp;
use Readonly;
# }}}1

our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
                 kFPHardCreate kFPStartEndFlag kFPLockUnlockFlag);

# define constants {{{1
our $VERSION = '0.69.0';
Readonly my $kFPByteRangeLock           => 1;   # AFP 2.0
Readonly my $kFPCloseVol                => 2;   # AFP 2.0
Readonly my $kFPCloseDir                => 3;   # AFP 2.0
Readonly my $kFPCloseFork               => 4;   # AFP 2.0
Readonly my $kFPCopyFile                => 5;   # AFP 2.0
Readonly my $kFPCreateDir               => 6;   # AFP 2.0
Readonly my $kFPCreateFile              => 7;   # AFP 2.0
Readonly my $kFPDelete                  => 8;   # AFP 2.0
Readonly my $kFPEnumerate               => 9;   # AFP 2.0
Readonly my $kFPFlush                   => 10;  # AFP 2.0
Readonly my $kFPFlushFork               => 11;  # AFP 2.0
Readonly my $kFPGetForkParms            => 14;  # AFP 2.0
Readonly my $kFPGetSrvrInfo             => 15;  # AFP 2.0
Readonly my $kFPGetSrvrParms            => 16;  # AFP 2.0
Readonly my $kFPGetVolParms             => 17;  # AFP 2.0
Readonly my $kFPLogin                   => 18;  # AFP 2.0
Readonly my $kFPLoginCont               => 19;  # AFP 2.0
Readonly my $kFPLogout                  => 20;  # AFP 2.0
Readonly my $kFPMapID                   => 21;  # AFP 2.0
Readonly my $kFPMapName                 => 22;  # AFP 2.0
Readonly my $kFPMoveAndRename           => 23;  # AFP 2.0
Readonly my $kFPOpenVol                 => 24;  # AFP 2.0
Readonly my $kFPOpenDir                 => 25;  # AFP 2.0
Readonly my $kFPOpenFork                => 26;  # AFP 2.0
Readonly my $kFPRead                    => 27;  # AFP 2.0
Readonly my $kFPRename                  => 28;  # AFP 2.0
Readonly my $kFPSetDirParms             => 29;  # AFP 2.0
Readonly my $kFPSetFileParms            => 30;  # AFP 2.0
Readonly my $kFPSetForkParms            => 31;  # AFP 2.0
Readonly my $kFPSetVolParms             => 32;  # AFP 2.0
Readonly my $kFPWrite                   => 33;  # AFP 2.0
Readonly my $kFPGetFileDirParms         => 34;  # AFP 2.0
Readonly my $kFPSetFileDirParms         => 35;  # AFP 2.0
Readonly my $kFPChangePassword          => 36;  # AFP 2.0
Readonly my $kFPGetUserInfo             => 37;  # AFP 2.0
Readonly my $kFPGetSrvrMsg              => 38;  # AFP 2.1
Readonly my $kFPCreateID                => 39;  # AFP 2.1
Readonly my $kFPDeleteID                => 40;  # AFP 2.1
Readonly my $kFPResolveID               => 41;  # AFP 2.1
Readonly my $kFPExchangeFiles           => 42;  # AFP 2.1
Readonly my $kFPCatSearch               => 43;  # AFP 2.1
Readonly my $kFPOpenDT                  => 48;  # AFP 2.0
Readonly my $kFPCloseDT                 => 49;  # AFP 2.0
Readonly my $kFPGetIcon                 => 51;  # AFP 2.0
Readonly my $kFPGetIconInfo             => 52;  # AFP 2.0
Readonly my $kFPAddAPPL                 => 53;  # AFP 2.0
Readonly my $kFPRemoveAPPL              => 54;  # AFP 2.0
Readonly my $kFPGetAPPL                 => 55;  # AFP 2.0
Readonly my $kFPAddComment              => 56;  # AFP 2.0
Readonly my $kFPRemoveComment           => 57;  # AFP 2.0
Readonly my $kFPGetComment              => 58;  # AFP 2.0
Readonly my $kFPByteRangeLockExt        => 59;  # AFP 3.0
Readonly my $kFPReadExt                 => 60;  # AFP 3.0
Readonly my $kFPWriteExt                => 61;  # AFP 3.0
Readonly my $kFPGetAuthMethods          => 62;  # AFP 3.0
Readonly my $kFPLoginExt                => 63;  # AFP 3.0
Readonly my $kFPGetSessionToken         => 64;  # AFP 3.0
Readonly my $kFPDisconnectOldSession    => 65;  # AFP 3.0
Readonly my $kFPEnumerateExt            => 66;  # AFP 3.0
Readonly my $kFPCatSearchExt            => 67;  # AFP 3.0
Readonly my $kFPEnumerateExt2           => 68;  # AFP 3.1
Readonly my $kFPGetExtAttr              => 69;  # AFP 3.2
Readonly my $kFPSetExtAttr              => 70;  # AFP 3.2
Readonly my $kFPRemoveExtAttr           => 71;  # AFP 3.2
Readonly my $kFPListExtAttrs            => 72;  # AFP 3.2
Readonly my $kFPGetACL                  => 73;  # AFP 3.2
Readonly my $kFPSetACL                  => 74;  # AFP 3.2
Readonly my $kFPAccess                  => 75;  # AFP 3.2
Readonly my $kFPSpotlightRPC            => 76;  # AFP 3.2+ (10.5)
Readonly my $kFPSyncDir                 => 78;  # AFP 3.2+ (10.5)
Readonly my $kFPSyncFork                => 79;  # AFP 3.2+ (10.5)
Readonly my $kFPZzzzz                   => 122; # AFP 2.3
Readonly my $kFPAddIcon                 => 192; # AFP 2.0
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
##        push(@logparms, { level => $DEBUG, file => 'STDERR' });
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
        return if not exists $options{Attribute};
        $ParamsBlock .= pack('n', $options{Attribute});
    }

    if ($Bitmap & kFPCreateDateBit) {
        return if not exists $options{CreateDate};
        my $time = $options{CreateDate} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPModDateBit) {
        return if not exists $options{ModDate};
        my $time = $options{ModDate} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPBackupDateBit) {
        return if not exists $options{BackupDate};
        my $time = $options{BackupDate} - globalTimeOffset;
        $ParamsBlock .= pack('N', long_convert($time));
    }

    if ($Bitmap & kFPFinderInfoBit) {
        return if not exists $options{FinderInfo};
        $ParamsBlock .= pack('a[32]', $options{FinderInfo});
    }

    if ($Bitmap & kFPOwnerIDBit) {
        return if not exists $options{OwnerID};
        $ParamsBlock .= pack('N', $options{OwnerID});
    }

    if ($Bitmap & kFPGroupIDBit) {
        return if not exists $options{GroupID};
        $ParamsBlock .= pack('N', $options{GroupID});
    }

    if ($Bitmap & kFPAccessRightsBit) {
        return if not exists $options{AccessRights};
        $ParamsBlock .= pack('N', $options{AccessRights});
    }

    # kFPLaunchLimitBit? what it do? can has knows?

    if ($Bitmap & kFPUnixPrivsBit) {
        return if not exists $options{UnixUID};
        return if not exists $options{UnixGID};
        return if not exists $options{UnixPerms};
        return if not exists $options{UnixAccessRights};

        $ParamsBlock .= pack('NNNN', @options{'UnixUID', 'UnixGID', 'UnixPerms',
                                              'UnixAccessRights'});
    }

    return $ParamsBlock;
} # }}}1

sub FPAccess { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        Bitmap      => { type => SCALAR, default => 0 },
        UUID        => {
            type    => SCALAR,
            regex   => qr{^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$}i,
        },
        ReqAccess   => {
            type        => SCALAR,
            callbacks   => {
                'valid access flags' => sub {
                    my $mask = (KAUTH_VNODE_GENERIC_ALL_BITS |
                            KAUTH_VNODE_WRITE_RIGHTS);
                    !($_[0] & ~$mask);
                },
            }
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack('CxnNna[16]Na*', $kFPAccess,
            @options{'VolumeID', 'DirectoryID', 'Bitmap',},
            uuid_pack($options{UUID}), $options{ReqAccess},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddAPPL { # {{{1
    my($self, @options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        FileCreator => { type => SCALAR },
        ApplTag     => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack('CxnNNNa*', $kFPAddAPPL,
            @options{'DTRefNum', 'DirectoryID', 'FileCreator', 'ApplTag'},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddComment { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
        Comment     => { type => SCALAR },
    } );

    my $msg = pack('CxnNa*x![s]C/a', $kFPAddComment,
            @options{'DTRefNum', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $options{Comment});
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddIcon { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        FileCreator => { type => SCALAR },
        FileType    => { type => SCALAR },
        IconType    => { type => SCALAR },
        IconTag     => { type => SCALAR },
        BitmapSize  => { type => SCALAR },
        IconBitmap  => { type => SCALAR },
    } );

    my $msg = pack('CxnNNCxNn', $kFPAddIcon,
            @options{'DTRefNum', 'FileCreator', 'FileType', 'IconType',
                     'IconTag', 'BitmapSize'});
    return $self->SendAFPWrite($msg, \$options{IconBitmap});
} # }}}1

sub FPByteRangeLock { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flags       => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { !(~0x81 & $_[0]) },
            }
        },
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        Length      => { type => SCALAR },
    } );

    my $msg = pack('CCnNN', $kFPByteRangeLock,
            @options{'Flags', 'OForkRefNum'},
            long_convert($options{Offset}),
            long_convert($options{Length}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') if not wantarray();
        return($rc, unpack('N', $resp));
    }
    return $rc;
} # }}}1

sub FPByteRangeLockExt { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flags       => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { !(~0x81 & $_[0]) },
            }
        },
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        Length      => { type => SCALAR },
    } );

    my $msg = pack('CCnNNNN', $kFPByteRangeLockExt,
            @options{'Flags', 'OForkRefNum'},
            ll_convert($options{Offset}),
            ll_convert($options{Length}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    if ($rc == kFPNoErr) {
        croak('Need to accept returned list') if not wantarray();
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
            if not exists $options{VolumeID};
    croak('ReqMatches must be provided')
            if not exists $options{ReqMatches};
    $options{CatalogPosition}       ||= q{};
    $options{FileRsltBitmap}        ||= 0;
    $options{DirectoryRsltBitmap}   ||= 0;
    $options{ReqBitmap}             ||= 0;

    my $msg = pack('CxnNx[4]a[16]nnN', $kFPCatSearch,
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
    my ($self, @options) = @_;
    DEBUG('called ', (caller(0))[3]);

    my($UAM, $UserName, $UserAuthInfo, $resp_r) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                { type => SCALAR, optional => 1, default => q{} },
                { type => SCALARREF, optional => 1, default => \q{} });

    my $msg = pack('CxC/a*x![s]C/a*x![s]a*', $kFPChangePassword, $UAM,
            $UserName, $UserAuthInfo);
    return $self->SendAFPMessage($msg, $resp_r, 1);
} # }}}1

sub FPCloseDir { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $DirectoryID) = 
            validate_pos(@options, { type => SCALAR }, { type => SCALAR });

    return $self->SendAFPMessage(pack('CxnN', $kFPCloseDir, $VolumeID,
            $DirectoryID));
} # }}}1

sub FPCloseDT { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($DTRefNum) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPCloseDT, $DTRefNum));
} # }}}1

sub FPCloseFork { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($OForkRefNum) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPCloseFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPCloseVol { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPCloseVol, $VolumeID), undef, 1);
} # }}}1

sub FPCopyFile { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        SourceVolumeID      => { type => SCALAR },
        SourceDirectoryID   => { type => SCALAR },
        DestVolumeID        => { type => SCALAR },
        DestDirectoryID     => { type => SCALAR },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
        NewType             => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        NewName             => { type => SCALAR },
    } );

    my $msg = pack('CxnNnNa*a*a*', $kFPCopyFile,
            @options{'SourceVolumeID', 'SourceDirectoryID',
                     'DestVolumeID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPCreateDir { # {{{1
    my($self, @options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CxnNa*', $kFPCreateDir,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})), \$resp, 1);
    return($rc, unpack('N', $resp))
            if $rc == kFPNoErr and wantarray();
    return $rc;
} # }}}1

sub FPCreateFile { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
             VolumeID       => { type => SCALAR },
             DirectoryID    => { type => SCALAR },
             PathType       => {
                 type       => SCALAR,
                 callbacks  => {
                     'valid path type' => sub {
                         $_[0] == kFPShortName || $_[0] == kFPLongName ||
                         $_[0] == kFPUTF8Name
                     }
                 }
             },
             Pathname       => { type => SCALAR },
             Flag           => { type => SCALAR, default => 0 },
    } );

    return $self->SendAFPMessage(pack('CCnNa*', $kFPCreateFile,
            @options{'Flag', 'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})), undef, 1);
} # }}}1

sub FPCreateID { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $msg = pack('CxnNa*', $kFPCreateID,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    return($rc, unpack('N', $resp));
} # }}}1

sub FPDelete { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $DirectoryID, $PathType, $Pathname) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                {
                    type => SCALAR,
                    callbacks  => {
                        'valid path type' => sub {
                            $_[0] == kFPShortName || $_[0] == kFPLongName ||
                            $_[0] == kFPUTF8Name
                        }
                    }
                },
                { type => SCALAR });

    return $self->SendAFPMessage(pack('CxnNa*', $kFPDelete, $VolumeID,
            $DirectoryID, PackagePath($PathType, $Pathname)), undef, 1);
} # }}}1

sub FPDeleteID { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $FileID) = validate_pos(@options,
            { type => SCALAR }, { type => SCALAR });

    return $self->SendAFPMessage(pack('CxnN', $kFPDeleteID, $VolumeID,
            $FileID));
} # }}}1

sub FPDisconnectOldSession { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Type, $Token) = validate_pos(@options,
            { type => SCALAR }, { type => SCALAR });

    return $self->SendAFPMessage(pack('CxnN/a', $kFPDisconnectOldSession,
            $Type, $Token));
} # }}}1

sub FPEnumerate { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xFFFF & $_[0]) },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xBFFF & $_[0]) },
            },
        },
        ReqCount        => { type => SCALAR },
        StartIndex      => { type => SCALAR },
        MaxReplySize    => { type => SCALAR },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );
    croak('Must accept array return') if not wantarray();

    my $msg = pack('CxnNnnnnna*', $kFPEnumerate,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xFFFF & $_[0]) },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xBFFF & $_[0]) },
            },
        },
        ReqCount        => { type => SCALAR },
        StartIndex      => { type => SCALAR },
        MaxReplySize    => { type => SCALAR },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );
    croak('Must accept array return') if not wantarray();

    my $msg = pack("CxnNnnnnna*", $kFPEnumerateExt,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xFFFF & $_[0]) },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xBFFF & $_[0]) },
            },
        },
        ReqCount        => { type => SCALAR },
        StartIndex      => { type => SCALAR },
        MaxReplySize    => { type => SCALAR },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );
    croak('Must accept array return') if not wantarray();

    my $msg = pack('CxnNnnnNNa*', $kFPEnumerateExt2,
            @options{'VolumeID', 'DirectoryID', 'FileBitmap', 'DirectoryBitmap',
                     'ReqCount', 'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID            => { type => SCALAR },
        SourceDirectoryID   => { type => SCALAR },
        DestDirectoryID     => { type => SCALAR },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
    } );

    my $msg = pack('CxnNNa*a*', $kFPExchangeFiles,
            @options{'VolumeID', 'SourceDirectoryID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}));
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPFlush { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPFlush, $VolumeID), undef, 1);
} # }}}1

sub FPFlushFork { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($OForkRefNum) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPFlushFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPGetACL { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        Bitmap          => {
            type        => SCALAR,
            default     => kFileSec_ACL,
            callbacks   => {
                'valid flags' => sub {
                    my $mask = kFileSec_UUID | kFileSec_GRPUUID |
                            kFileSec_ACL;
                    !($_[0] & ~$mask);
                },
            }
        },
        MaxReplySize    => { type => SCALAR, default => 0 },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                     $_[0] == kFPShortName || $_[0] == kFPLongName ||
                     $_[0] == kFPUTF8Name
                }
            }
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack('CxnNnNa*', $kFPGetACL,
            @options{'VolumeID', 'DirectoryID', 'Bitmap', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    my %rvals;
    ($rvals{Bitmap}, $resp) = unpack('na*', $resp);

    if ($rvals{Bitmap} & kFileSec_UUID) {
        ($rvals{UUID}, $resp) = unpack('a[16]a*', $resp);
        $rvals{UUID} = uuid_unpack($rvals{UUID});
    }

    if ($rvals{Bitmap} & kFileSec_GRPUUID) {
        ($rvals{GRPUUID}, $resp) = unpack('a[16]a*', $resp);
        $rvals{GRPUUID} = uuid_unpack($rvals{GRPUUID});
    }

    if ($rvals{Bitmap} & kFileSec_ACL) {
        my $acl_entrycount;
        ($acl_entrycount, $rvals{acl_flags}, $resp) = unpack('NNa*', $resp);
        my @entries = unpack('(a[16]NN)[' . $acl_entrycount . ']', $resp);
        my @acl_ace = ();
        for my $i (0 .. $acl_entrycount - 1) {
            $acl_ace[$i] = {
                             ace_applicable => uuid_unpack(shift(@entries)),
                             ace_flags      => shift(@entries),
                             ace_rights     => shift(@entries),
                           };
        }
        $rvals{acl_ace} = [ @acl_ace ];
    }
    return($rc, %rvals);
} # }}}1

sub FPGetAPPL { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        FileCreator => { type => SCALAR },
        APPLIndex   => { type => SCALAR },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { !(~0xFFFF & $_[0]) },
            },
        },
    } );

    my $msg = pack('CxnNnn', $kFPGetAPPL,
            @options{'DTRefNum', 'FileCreator', 'APPLIndex', 'Bitmap'});

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    my($Bitmap_n, $APPLTag, $data) = unpack('nNa*', $resp);
    my $info = _ParseFileParms($Bitmap_n, $data);
    my %rvals = (
                  Bitmap            => $Bitmap_n,
                  APPLTag           => $APPLTag,
                  FileParameters    => $info,
                );
    return($rc, %rvals);
} # }}}1

sub FPGetAuthMethods { # {{{1
    my($self, @options) = @_;
    DEBUG('called ', (caller(0))[3]);

    my($Flags, $PathType, $Pathname, $resp_r) = validate_pos(@options,
            {
                type        => SCALAR,
                callbacks   => {
                    'valid flags' => sub { $_[0] == 0 }
                }
            },
            {
                type        => SCALAR,
                callbacks   => {
                    'valid path type' => sub {
                        $_[0] == kFPShortName || $_[0] == kFPLongName ||
                        $_[0] == kFPUTF8Name
                    }
                }
            },
            { type => SCALAR },
            { type => SCALARREF });

    my $msg = pack('CxCa*', $kFPGetAuthMethods, $Flags,
            PackagePath($PathType, $Pathname));
    my($resp, @UAMStrings);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    ($Flags, @UAMStrings) = unpack('CC/(C/a)', $resp);
    ${$resp_r} = { Flags => $Flags, UAMStrings => [ @UAMStrings ] };
    return $rc;
} # }}}1

sub FPGetComment { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                     $_[0] == kFPShortName || $_[0] == kFPLongName ||
                     $_[0] == kFPUTF8Name
                },
            }
        },
        Pathname    => { type => SCALAR },
    } );
    croak('Need to accept returned list') unless wantarray();

    my $msg = pack('CxnNa*', $kFPGetComment,
            @options{'DTRefNum', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    return($rc, unpack('C/a', $resp));
} # }}}1

sub FPGetExtAttr { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { $_[0] == kXAttrNoFollow || $_[0] == 0 },
            }
        },
        Offset          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid offset' => sub { $_[0] == 0 },
            }
        },
        ReqCount        => {
            type        => SCALAR,
            default     => -1,
            callbacks   => {
                'valid count' => sub { $_[0] == -1 },
            },
        },
        MaxReplySize    => { type => SCALAR, default => 0 },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
        Name            => { type => SCALAR },
    } );

    my $msg = pack('CxnNnNNNNNa*x![s]n/a*', $kFPGetExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            ll_convert($options{Offset}),
            ll_convert($options{ReqCount}),
            $options{MaxReplySize},
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{Name})));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    my %rvals;
    if ($options{MaxReplySize} > 0) {
        @rvals{'Bitmap', 'AttributeData'} = unpack('nN/a*', $resp);
    }
    else {
        @rvals{'Bitmap', 'DataLength'} = unpack('nN', $resp);
    }
    return($rc, %rvals);
} # }}}1

sub FPGetFileDirParms { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xFFFF & $_[0]) },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xBFFF & $_[0]) },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack('CxnNnna*', $kFPGetFileDirParms,
            @options{'VolumeID','DirectoryID','FileBitmap','DirectoryBitmap'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    return($rc, _ParseFileDirParms($resp));
} # }}}1

sub FPGetForkParms { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($OForkRefNum, $Bitmap, $resp_r) = validate_pos(@options,
            { type => SCALAR },
            {
                type        => SCALAR,
                callbacks   => {
                    'valid bitmap' => sub { !(~0xFFFF & $_[0]) }
                }
            },
            { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', $kFPGetForkParms, $OForkRefNum,
            $Bitmap), \$resp);
    return $rc if $rc != kFPNoErr;
    ${$resp_r} = _ParseFileParms(unpack('na*', $resp));
    return $rc;
} # }}}1

sub FPGetIcon { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        FileCreator => { type => SCALAR },
        FileType    => { type => SCALAR },
        IconType    => { type => SCALAR },
        Length      => { type => SCALAR },
    } );

    my $msg = pack('CxnNNCxn', $kFPGetIcon,
            @options{'DTRefNum', 'FileCreator', 'FileType', 'IconType',
                     'Length'});
    croak('Need to accept returned list') if not wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

sub FPGetIconInfo { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($DTRefNum, $FileCreator, $IconIndex, $resp_r) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                { type => SCALAR },
                { type => SCALARREF });
    
    my $resp;
    my $msg = pack('CxnNn', $kFPGetIconInfo, $DTRefNum, $FileCreator,
            $IconIndex);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != kFPNoErr;
    ${$resp_r} = {};
    @{${$resp_r}}{'IconTag', 'FileType', 'IconType', 'Size'} =
            unpack('NNCxn', $resp);
    return $rc;
} # }}}1

sub FPGetSessionToken { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Type, $timeStamp, $ID, $resp_r) = validate_pos(@options,
            {
                type        => SCALAR,
                callbacks   => {
                    'valid type' => {
                        $_[0] >= kLoginWithoutID &&
                            $_[0] <= kGetKerberosSessionKey
                    }
                }
            },
            { type => SCALAR },
            { type => SCALAR, optional => 1, default => q{} },
            { type => SCALARREF });

    my $resp;
    my $pack_mask = 'CxnN';
    my @params = ($kFPGetSessionToken, $Type, length($ID));
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
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($resp_r) = validate_pos(@options, { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cx', $kFPGetSrvrInfo), \$resp);
    # If the response was not kFPNoErr, the info block will not be present.
    return $rc if $rc != kFPNoErr;

    ${$resp_r} = _ParseSrvrInfo($resp);
    return $rc;
} # }}}1

sub FPGetSrvrMsg { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($MessageType, $MessageBitmap, $resp_r) =
            validate_pos(@options,
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid type' => sub { $_[0] == 0 || $_[0] == 1 }
                    }
                },
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid bitmap' => sub { !(~0x3 & $_[0]) }
                    }
                },
                { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', $kFPGetSrvrMsg, $MessageType,
            $MessageBitmap), \$resp);
    return $rc if $rc != kFPNoErr;
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
                   MessageType      => $MessageType,
                   MessageBitmap    => $MessageBitmap,
                   ServerMessage    => $ServerMessage,
                   Length           => $Length,
                 };
    return $rc;
} # }}}1

sub FPGetSrvrParms { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($resp_r) = validate_pos(@options, { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cx', $kFPGetSrvrParms), \$resp);
    # If the response was not kFPNoErr, the info block will not be present.
    return $rc if $rc != kFPNoErr;

    my $data = {};
    my ($time, @volinfo) = unpack('NC/(CC/a)', $resp);
    # AFP does not express times since 1 Jan 1970 00:00 GMT, but since 
    # 1 Jan 2000 00:00 GMT (I think GMT, anyway). Good call, Apple...
    ${$data}{ServerTime}    = long_unconvert($time) + globalTimeOffset;
    ${$data}{Volumes}       = [];
    while (scalar(@volinfo) > 0) {
        my $flags = shift @volinfo;
        my $volname = shift @volinfo;
        # The documentation from Apple says "HasUNIXPrivs" is the high
        # bit; ethereal seems to think it's the second bit, not the high
        # bit. I'll have to see how to turn that on somewhere to find out.
        # Also, looks like the HasUNIXPrivs bit is gone as of AFP 3.2...
        push(@{${$data}{Volumes}}, { HasPassword    => $flags & 0x80,
                                     HasConfigInfo  => $flags & 0x01,
                                     VolName        => $volname } );
    }
    ${$resp_r} = $data;
    return $rc;
} # }}}1

sub FPGetUserInfo { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Flags, $UserID, $Bitmap, $resp_r) =
            validate_pos(@options,
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid type' => sub { !(~0x1 & $_[0]) }
                    }
                },
                { type => SCALAR },
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid bitmap' => sub { !(~0x7 & $_[0]) }
                    }
                },
                { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CCNn', $kFPGetUserInfo, $Flags,
            $UserID, $Bitmap), \$resp);

    return $rc if $rc != kFPNoErr;
    
    my $rbmp = unpack('n', $resp);
    my $offset = 2;
    ${$resp_r} = {};
    if ($rbmp & 0x1) { # Get User ID bit
        ${$resp_r}->{UserID} = unpack('x[' . $offset . ']N', $resp);
        $offset += 4;
    }
    if ($rbmp & 0x2) {
        if (Net::AFP::Versions::CompareByVersionNum($self, 2, 1,
                kFPVerAtLeast)) {
            if (exists ${$resp_r}->{UserID}) {
                ${$resp_r}->{PrimaryGroupID} = ${$resp_r}->{UserID};
            }
        }
        else {
            ${$resp_r}->{PrimaryGroupID} =
                    unpack('x[' . $offset . ']N', $resp);
            $offset += 4;
        }
    }
    if ($rbmp & 0x4) {
        ${$resp_r}->{UUID} = uuid_unpack(unpack('x['.$offset.']a[16]', $resp));
        $offset += 16;
    }

    return $rc;
} # }}}1

sub FPGetVolParms { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $Bitmap, $resp_r) = validate_pos(@options,
            { type => SCALAR },
            {
                type        => SCALAR,
                callbacks   => {
                    'valid bitmap' => sub { !(~0xFFF & $_[0]) }
                }
            },
            { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxnn', $kFPGetVolParms, $VolumeID,
            $Bitmap), \$resp);
    return($rc) if $rc != kFPNoErr;
    ${$resp_r} = _ParseVolParms($resp);
    return $rc;
} # }}}1

sub FPListExtAttrs { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { $_[0] == kXAttrNoFollow },
            }
        },
        ReqCount        => { type => SCALAR, default => 0 },
        StartIndex      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid index' => sub { $_[0] == 0 },
            }
        },
        MaxReplySize    => { type => SCALAR, default => 0 },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack('CxnNnnNNa*', $kFPListExtAttrs,
            @options{'VolumeID', 'DirectoryID', 'Bitmap', 'ReqCount',
                     'StartIndex', 'MaxReplySize'},
            PackagePath(@options{'PathType', 'Pathname'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    my %rvals;
    if ($options{MaxReplySize} > 0) {
        my $names;
        ($rvals{Bitmap}, $names) = unpack('nN/a*', $resp);
        $rvals{AttributeNames} =
                [ map { compose(decode_utf8($_)) } unpack('(Z*)*', $names) ];
    }
    else {
        @rvals{'Bitmap', 'DataLength'} = unpack('nN', $resp);
    }
    return($rc, %rvals);
} # }}}1

sub FPLogin { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($AFPVersion, $UAM, $UserAuthInfo) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                { type => SCALAR, optional => 1, default => q{} });

    my $msg = pack('CC/a*C/a*a*', $kFPLogin, $AFPVersion, $UAM, $UserAuthInfo);
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    
    croak('Need to accept returned list') if not wantarray();
    if ($rc == kFPAuthContinue and length($resp) >= 2) {
        $rvals{ID} = unpack('n', $resp);
        if (length($resp) > 2) {
            $rvals{UserAuthInfo} = substr($resp, 2);
        }
    }
    return($rc, %rvals);
} # }}}1

sub FPLoginCont { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($ID, $UserAuthInfo, $resp_r) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR, optional => 1, default => q{} },
                { type => SCALARREF, optional => 1, default => *foo{SCALAR} });

    my $resp;
    # Unlike FPLogin, the pad byte actually does need to be there.
    my $rc = $self->SendAFPMessage(pack('Cxna*', $kFPLoginCont, $ID,
            $UserAuthInfo), \$resp);
    
    if (($rc == kFPAuthContinue || $rc == kFPNoErr)
            && defined($resp)) {
        ${$resp_r} = {};
        my $offset = 0;
        if ($rc == kFPAuthContinue) {
            ${$resp_r}->{ID} = unpack('n', $resp);
            $offset = 2;
        }
        if (length($resp) > $offset) {
            ${$resp_r}->{UserAuthInfo} = substr($resp, $offset);
        }
    }
    return $rc;
} # }}}1

sub FPLoginExt { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flags           => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { $_[0] == 0 },
            },
        },
        AFPVersion      => { type => SCALAR },
        UAM             => { type => SCALAR },
        UserNameType    => {
            type        => SCALAR,
            # The documentation says this should always be UTF8
            default     => kFPUTF8Name,
            callbacks   => {
                'valid type flag' => sub { $_[0] == kFPUTF8Name },
            }
        },
        UserName        => { type => SCALAR },
        # Documentation doesn't say this has to always be UTF8, but it's a
        # safe choice, and generally we don't give a damn
        PathType        => {
            type        => SCALAR,
            default     => kFPUTF8Name,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            },
        },
        Pathname        => {
            type        => SCALAR,
            default     => q{},
        },
        UserAuthInfo    => {
            type        => SCALAR,
            default     => q{},
        }
    } );

    my $msg = pack('CxnC/a*C/a*a*a*x![s]a*', $kFPLoginExt,
            @options{'Flags', 'AFPVersion', 'UAM'},
            PackagePath(@options{'UserNameType', 'UserName'}, 1),
            PackagePath(@options{'PathType', 'Pathname'}, 1),
            $options{UserAuthInfo});
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    
    croak('Need to accept returned list') if not wantarray();
    if ($rc == kFPAuthContinue and length($resp) >= 2) {
        $rvals{ID} = unpack('n', $resp);
        if (length($resp) > 2) {
            $rvals{UserAuthInfo} = substr($resp, 2);
        }
    }
    return($rc, %rvals);
} # }}}1

sub FPLogout { # {{{1
    my ($self) = @_;

    DEBUG('called ', (caller(0))[3]);

    return $self->SendAFPMessage(pack('Cx', $kFPLogout));
} # }}}1

sub FPMapID { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Subfunction, $ID, $resp_r) =
            validate_pos(@options,
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid subfunction' => sub {
                            $_[0] >= kUserIDToName &&
                                    $_[0] <= kGroupUUIDToUTF8Name
                        }
                    }
                },
                { type => SCALAR },
                { type => SCALARREF });

    my $resp;
    my $pack_mask = 'CC';
    my @pack_args = ($kFPMapID, $Subfunction);
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
    return $rc if $rc != kFPNoErr;
    if ($Subfunction == kUserUUIDToUTF8Name ||
            $Subfunction == kGroupUUIDToUTF8Name) {
        ${$resp_r} = {};
        @{${$resp_r}}{'Bitmap', 'NumericID', 'UTF8Name'} =
                unpack('NNn/a', $resp);
        ${${$resp_r}}{UTF8Name} =
                compose(decode_utf8(${$resp_r}->{UTF8Name}));
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my($Subfunction, $Name, $resp_r) =
            validate_pos(@options,
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid subfunction' => sub {
                            $_[0] >= kNameToUserID &&
                                    $_[0] <= kUTF8NameToGroupUUID
                        }
                    }
                },
                { type => SCALAR },
                { type => SCALARREF });

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
    my $msg = pack($pack_mask, $kFPMapName, $Subfunction, $Name);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != kFPNoErr;
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID            => { type => SCALAR },
        SourceDirectoryID   => { type => SCALAR },
        DestDirectoryID     => { type => SCALAR },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
        NewType             => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        NewName             => { type => SCALAR },
    } );

    my $msg = pack('CxnNNa*a*a*', $kFPMoveAndRename,
            @options{'VolumeID', 'SourceDirectoryID', 'DestDirectoryID'},
            PackagePath(@options{'SourcePathType', 'SourcePathname'}),
            PackagePath(@options{'DestPathType', 'DestPathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc;
} # }}}1

sub FPOpenDir { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $rc = $self->SendAFPMessage(pack('CxnNa*', $kFPOpenDir,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'})), \$resp);
    return $rc if $rc != kFPNoErr;
    croak('Need to accept returned list') if not wantarray();
    return($rc, unpack('N', $resp));
} # }}}1

sub FPOpenDT { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $resp_r) = validate_pos(@options,
            { type => SCALAR },
            { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack('Cxn', $kFPOpenDT, $VolumeID), \$resp);
    return $rc if $rc != kFPNoErr;
    (${$resp_r}) = unpack('n', $resp);
    return $rc;
} # }}}1

sub FPOpenFork { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flag        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flag bits' => sub { !(~0x80 & $_[0]) },
            },
        },
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { !(~0xFFFF & $_[0]) },
            },
        },
        AccessMode  => {
            type        => SCALAR,
            callbacks   => {
                'valid access mode' => sub { !(~0x33 & $_[0]) },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack('CCnNnna*', $kFPOpenFork,
            @options{'Flag', 'VolumeID', 'DirectoryID', 'Bitmap', 'AccessMode'},
            PackagePath(@options{'PathType', 'Pathname'}));

    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    croak('Need to accept returned list') if not wantarray();
    if ($rc == kFPNoErr) {
        my ($rBitmap, $OForkRefNum, $FileParameters) = unpack('nna*', $resp);
        %rvals = %{ _ParseFileParms($rBitmap, $FileParameters) };
        $rvals{OForkRefNum} = $OForkRefNum;
    }
    return($rc, %rvals);
} # }}}1

sub FPOpenVol { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Bitmap, $VolumeName, $Password, $resp_r) =
            validate_pos(@options,
            {
                type        => SCALAR,
                callbacks   => {
                    'valid bitmap' => sub { !(~0xFFF & $_[0]) }
                }
            },
            { type => SCALAR },
            { type => SCALAR | UNDEF, optional => 1, default => q{} },
            { type => SCALARREF });
    
    # Make sure the VolID bit is set, because it's kind of necessary.
    $Bitmap |= kFPVolIDBit;

    my $PackPattern = 'CxnCa*';
    my @PackArgs = ($kFPOpenVol, $Bitmap, length($VolumeName), $VolumeName);
    # Only append a password if one was provided. If not, we don't provide
    # it.
    if (defined $Password) {
        $PackPattern .= 'x![s]Z8';
        push(@PackArgs, $Password);
    }
    my $msg = pack($PackPattern, @PackArgs);

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc if $rc != kFPNoErr;
    ${$resp_r} = _ParseVolParms($resp);
    return $rc;
} # }}}1

sub FPRead { # {{{1
    my($self, @options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        ReqCount    => { type => SCALAR },
        NewLineMask => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid mask values' => sub { $_[0] >= 0 && $_[0] <= 0xFF },
            },
        },
        NewLineChar => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid char values' => sub { $_[0] >= 0 && $_[0] <= 0xFF },
            },
        },
    } );

    my $msg = pack('CxnNNCC', $kFPRead,
            @options{'OForkRefNum', 'Offset', 'ReqCount', 'NewLineMask',
                     'NewLineChar'});

    croak('Need to accept returned list') if not wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

sub FPReadExt { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        ReqCount    => { type => SCALAR },
    } );
    
    my $msg = pack('CxnNNNN', $kFPReadExt, $options{OForkRefNum},
            ll_convert($options{Offset}), ll_convert($options{ReqCount}));

    croak('Need to accept returned list') if not wantarray();
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

sub FPRemoveAPPL { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        DTRefNum    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        FileCreator => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack('CxnNNa*', $kFPRemoveAPPL,
            @options{'DTRefNum', 'DirectoryID', 'FileCreator'},
            PackagePath(@options{'PathType', 'Pathname'}));
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPRemoveComment { # {{{1
    my($self, @options) = @_;
    DEBUG('called ', (caller(0))[3]);

    my($DTRefNum, $DirectoryID, $PathType, $Pathname) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid path type' => sub {
                            $_[0] == kFPShortName || $_[0] == kFPLongName ||
                            $_[0] == kFPUTF8Name
                        }
                    }
                },
                { type => SCALAR });

    my $msg = pack('CxnNa*', $kFPRemoveComment, $DTRefNum, $DirectoryID,
            PackagePath($PathType, $Pathname));
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPRemoveExtAttr { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { $_[0] == kXAttrNoFollow || $_[0] == 0 },
            }
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            }
        },
        Pathname    => { type => SCALAR },
        Name        => { type => SCALAR },
    } );

    my $msg = pack('CxnNna*x![s]n/a*', $kFPRemoveExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{Name})));
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPRename { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID    => { type => SCALAR },
        DirectoryID => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
        NewType     => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        NewName     => { type => SCALAR },
    } );

    my $msg = pack('CxnNa*a*', $kFPRename,
            @options{'VolumeID', 'DirectoryID'},
            PackagePath(@options{'PathType', 'Pathname'}),
            PackagePath(@options{'NewType', 'NewName'}));
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPResolveID { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $FileID, $Bitmap, $resp_r) =
            validate_pos(@options,
                { type => SCALAR },
                { type => SCALAR },
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid bitmap' => sub { !(~0xFFFF & $_[0]) }
                    }
                },
                { type => SCALARREF });

    my $resp;
    my $msg = pack('CxnNn', $kFPResolveID, $VolumeID, $FileID, $Bitmap);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != kFPNoErr;
    my($Bitmap_n, $data) = unpack('na*', $resp);
    my $info = _ParseFileParms($Bitmap_n, $data);
    ${$resp_r} = {
                   Bitmap               => $Bitmap_n,
                   RequestedParameters  => $info,
                 };
    return $rc;
} # }}}1

sub FPSetACL { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
            VolumeID    => { type => SCALAR },
            DirectoryID => { type => SCALAR },
            Bitmap      => {
                type        => SCALAR,
                default     => kFileSec_ACL,
                callbacks   => {
                    'valid flags' => sub {
                        my $mask = kFileSec_UUID | kFileSec_GRPUUID |
                                kFileSec_ACL | kFileSec_REMOVEACL |
                                kFileSec_Inherit;
                        !($_[0] & ~$mask);
                    },
                }
            },
            PathType    => {
                type        => SCALAR,
                callbacks   => {
                    'valid path type' => sub {
                         $_[0] == kFPShortName || $_[0] == kFPLongName ||
                         $_[0] == kFPUTF8Name
                    }
                }
            },
            Pathname    => { type => SCALAR },
            UUID        => { type => SCALAR, optional => 1 },
            GRPUUID     => { type => SCALAR, optional => 1 },
            acl_ace     => { type => ARRAYREF, optional => 1 },
            acl_flags   => { type => SCALAR, optional => 1 },
    } );

    my $msg = pack('CxnNna*x![s]', $kFPSetACL,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}));
    if ($options{Bitmap} & kFileSec_UUID) {
        croak('UUID must be provided')
                if not exists $options{UUID};
        $msg .= uuid_pack($options{UUID});
    }
    if ($options{Bitmap} & kFileSec_GRPUUID) {
        croak('GRPUUID must be provided')
                if not exists $options{GRPUUID};
        $msg .= uuid_pack($options{GRPUUID});
    }
    if ($options{Bitmap} & kFileSec_ACL) {
        croak('acl_ace must be provided')
                if not exists $options{acl_ace};
        croak('acl_flags must be provided')
                if not exists $options{acl_flags};
        my @ace_list;
        foreach my $ace (@{$options{acl_ace}}) {
            push(@ace_list, pack('a[16]NN',
                    uuid_pack(${$ace}{ace_applicable}),
                    @{$ace}{'ace_flags', 'ace_rights'}));
        }
        $msg .= pack('NN(a*)[' . scalar(@ace_list) . ']', scalar(@ace_list),
            $options{acl_flags}, @ace_list);
    }
    
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetDirParms { # {{{1
    my($self, @options) = @_;
    
    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID            => { type => SCALAR },
        DirectoryID         => { type => SCALAR },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = kFPAttributeBit | kFPCreateDateBit |
                            kFPModDateBit | kFPBackupDateBit |
                            kFPFinderInfoBit | kFPOwnerIDBit |
                            kFPGroupIDBit | kFPAccessRightsBit |
                            kFPUnixPrivsBit;
                    !(~$mask & $_[0])
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attribute           => { type => SCALAR, optional => 1 },
        CreateDate          => { type => SCALAR, optional => 1 },
        ModDate             => { type => SCALAR, optional => 1 },
        BackupDate          => { type => SCALAR, optional => 1 },
        FinderInfo          => { type => SCALAR, optional => 1 },
        OwnerID             => { type => SCALAR, optional => 1 },
        GroupID             => { type => SCALAR, optional => 1 },
        AccessRights        => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', $kFPSetDirParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetExtAttr { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID        => { type => SCALAR },
        DirectoryID     => { type => SCALAR },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub {
                    my $mask = kXAttrNoFollow | kXAttrCreate | kXAttrReplace;
                    !(~$mask & $_[0]);
                },
            },
        },
        Offset          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid offset' => sub { $_[0] == 0 },
            }
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
        Name            => { type => SCALAR },
        AttributeData   => { type => SCALAR },
    } );

    my $msg = pack('CxnNnNNa*x![s]n/a*N/a*', $kFPSetExtAttr,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            ll_convert($options{Offset}),
            PackagePath(@options{'PathType', 'Pathname'}),
            encode_utf8(decompose($options{Name})),
            $options{AttributeData});
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetFileDirParms { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID            => { type => SCALAR },
        DirectoryID         => { type => SCALAR },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = kFPAttributeBit | kFPCreateDateBit |
                            kFPModDateBit | kFPBackupDateBit |
                            kFPFinderInfoBit | kFPUnixPrivsBit;
                    !(~$mask & $_[0])
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attribute           => { type => SCALAR, optional => 1 },
        CreateDate          => { type => SCALAR, optional => 1 },
        ModDate             => { type => SCALAR, optional => 1 },
        BackupDate          => { type => SCALAR, optional => 1 },
        FinderInfo          => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', $kFPSetFileDirParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetFileParms { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        VolumeID            => { type => SCALAR },
        DirectoryID         => { type => SCALAR },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = kFPAttributeBit | kFPCreateDateBit |
                            kFPModDateBit | kFPBackupDateBit |
                            kFPFinderInfoBit | kFPLaunchLimitBit |
                            kFPUnixPrivsBit;
                    !(~$mask & $_[0])
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == kFPShortName || $_[0] == kFPLongName ||
                    $_[0] == kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attribute           => { type => SCALAR, optional => 1 },
        CreateDate          => { type => SCALAR, optional => 1 },
        ModDate             => { type => SCALAR, optional => 1 },
        BackupDate          => { type => SCALAR, optional => 1 },
        FinderInfo          => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, %options);
    return kFPParamErr if !defined $ParamsBlock;

    my $msg = pack('CxnNna*x![s]a*', $kFPSetFileParms,
            @options{'VolumeID', 'DirectoryID', 'Bitmap'},
            PackagePath(@options{'PathType', 'Pathname'}),
            $ParamsBlock);
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetForkParms { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($OForkRefNum, $Bitmap, $ForkLen) = validate_pos(@options,
            { type => SCALAR },
            {
                type        => SCALAR,
                callbacks   => {
                    'valid bitmap' => sub { !(~0x4E00 & $_[0]) }
                }
            },
            { type => SCALAR });

    my $packed = undef;
    if (($Bitmap & kFPDataForkLenBit) or
        ($Bitmap & kFPRsrcForkLenBit)) {
        $packed = pack('N', $ForkLen);
    }
    elsif (($Bitmap & kFPExtDataForkLenBit) or
             ($Bitmap & kFPExtRsrcForkLenBit)) {
        $packed = pack('NN', ll_convert($ForkLen));
    }

    return $self->SendAFPMessage(pack('Cxnna*', $kFPSetForkParms, $OForkRefNum,
            $Bitmap, $packed), undef, 1);
} # }}}1

sub FPSetVolParms { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $Bitmap, $BackupDate) =
            validate_pos(@options,
                { type => SCALAR },
                {
                    type        => SCALAR,
                    callbacks   => {
                        'valid bitmap' => sub { !(~0x0010 & $_[0]) }
                    }
                },
                { type => SCALAR });
    return $self->SendAFPMessage(pack('CxnnN', $kFPSetVolParms, $VolumeID,
            $Bitmap, $BackupDate), undef, 1);
} # }}}1

sub FPSyncDir { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($VolumeID, $DirectoryID) = validate_pos(@options,
            { type => SCALAR },
            { type => SCALAR });

    return $self->SendAFPMessage(pack('CxnN', $kFPSyncDir, $VolumeID,
            $DirectoryID), undef, 1);
} # }}}1

sub FPSyncFork { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($OForkRefNum) = validate_pos(@options, { type => SCALAR });

    return $self->SendAFPMessage(pack('Cxn', $kFPSyncFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPWrite { # {{{1
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flag        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flag bits' => sub { !(~0x80 & $_[0]) },
            },
        },
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        ForkData    => { type => SCALARREF },
        ReqCount    => { type => SCALAR, optional => 1 },
    } );
    $options{ReqCount} ||= length(${$options{ForkData}});

    my $msg = pack('CCnNN', $kFPWrite,
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
    my($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);
    my %options = validate(@options, {
        Flag        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flag bits' => sub { !(~0x80 & $_[0]) },
            },
        },
        OForkRefNum => { type => SCALAR },
        Offset      => { type => SCALAR },
        ForkData    => { type => SCALARREF },
        ReqCount    => { type => SCALAR, optional => 1 },
    } );
    $options{ReqCount} ||= length(${$options{ForkData}});

    my $msg = pack('CCnNNNN', $kFPWriteExt, @options{'Flag', 'OForkRefNum'},
            ll_convert($options{Offset}), ll_convert($options{ReqCount}));

    my $resp;
    my $rc = $self->SendAFPWrite($msg, @options{'ForkData', 'ReqCount'},
            \$resp);
    if ($rc == kFPNoErr && wantarray()) {
        return($rc, ll_unconvert(unpack('NN', $resp)));
    }
    return $rc;
} # }}}1

sub FPZzzzz { # {{{1
    my ($self, @options) = @_;

    DEBUG('called ', (caller(0))[3]);

    my($Flags) = validate_pos(@options,
            {
                type        => SCALAR,
                callbacks   => {
                    'valid flags' => sub { !(~0x3 & $_[0]) }
                },
                optional    => 1,
                default     => 0
            });

    return $self->SendAFPMessage(pack('CxN', $kFPZzzzz, $Flags));
} # }}}1

1;
# vim: ts=4 fdm=marker
