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
use Net::AFP::FileAttrs qw(:DEFAULT !:common);
use Net::AFP::DirParms;
use Net::AFP::DirAttrs;
use Net::AFP::MapParms;
use Net::AFP::Versions;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Exporter qw(import);
use Log::Log4perl;
use Params::Validate qw(:all);
use Carp;
use Readonly;
use Data::Dumper;
use Scalar::Util qw(looks_like_number);

my $has_UUID = 0;
eval { require UUID; 1; } and do { $has_UUID = 1; };
# }}}1

our @EXPORT = qw($kFPShortName $kFPLongName $kFPUTF8Name $kFPSoftCreate
                 $kFPHardCreate $kFPStartEndFlag $kFPLockUnlockFlag
                 $kFPAccessReadOnly $kFPAccessWriteOnly $kFPAccessReadWrite
                 $kFPResourceDataFlag);

# define constants {{{1
our $VERSION = '0.69.0';
Readonly my $kFPByteRangeLock           => 1;   # AFP 1.1
Readonly my $kFPCloseVol                => 2;   # AFP 1.1
Readonly my $kFPCloseDir                => 3;   # AFP 1.1
Readonly my $kFPCloseFork               => 4;   # AFP 1.1
Readonly my $kFPCopyFile                => 5;   # AFP 1.1
Readonly my $kFPCreateDir               => 6;   # AFP 1.1
Readonly my $kFPCreateFile              => 7;   # AFP 1.1
Readonly my $kFPDelete                  => 8;   # AFP 1.1
Readonly my $kFPEnumerate               => 9;   # AFP 1.1
Readonly my $kFPFlush                   => 10;  # AFP 1.1
Readonly my $kFPFlushFork               => 11;  # AFP 1.1
Readonly my $kFPGetForkParms            => 14;  # AFP 1.1
Readonly my $kFPGetSrvrInfo             => 15;  # AFP 1.1
Readonly my $kFPGetSrvrParms            => 16;  # AFP 1.1
Readonly my $kFPGetVolParms             => 17;  # AFP 1.1
Readonly my $kFPLogin                   => 18;  # AFP 1.1
Readonly my $kFPLoginCont               => 19;  # AFP 1.1
Readonly my $kFPLogout                  => 20;  # AFP 1.1
Readonly my $kFPMapID                   => 21;  # AFP 1.1
Readonly my $kFPMapName                 => 22;  # AFP 1.1
Readonly my $kFPMoveAndRename           => 23;  # AFP 1.1
Readonly my $kFPOpenVol                 => 24;  # AFP 1.1
Readonly my $kFPOpenDir                 => 25;  # AFP 1.1
Readonly my $kFPOpenFork                => 26;  # AFP 1.1
Readonly my $kFPRead                    => 27;  # AFP 1.1
Readonly my $kFPRename                  => 28;  # AFP 1.1
Readonly my $kFPSetDirParms             => 29;  # AFP 1.1
Readonly my $kFPSetFileParms            => 30;  # AFP 1.1
Readonly my $kFPSetForkParms            => 31;  # AFP 1.1
Readonly my $kFPSetVolParms             => 32;  # AFP 1.1
Readonly my $kFPWrite                   => 33;  # AFP 1.1
Readonly my $kFPGetFileDirParms         => 34;  # AFP 1.1
Readonly my $kFPSetFileDirParms         => 35;  # AFP 1.1
Readonly my $kFPChangePassword          => 36;  # AFP 2.0
Readonly my $kFPGetUserInfo             => 37;  # AFP 2.0
Readonly my $kFPGetSrvrMsg              => 38;  # AFP 2.1
Readonly my $kFPCreateID                => 39;  # AFP 2.1
Readonly my $kFPDeleteID                => 40;  # AFP 2.1
Readonly my $kFPResolveID               => 41;  # AFP 2.1
Readonly my $kFPExchangeFiles           => 42;  # AFP 2.1
Readonly my $kFPCatSearch               => 43;  # AFP 2.1
Readonly my $kFPOpenDT                  => 48;  # AFP 1.1
Readonly my $kFPCloseDT                 => 49;  # AFP 1.1
Readonly my $kFPGetIcon                 => 51;  # AFP 1.1
Readonly my $kFPGetIconInfo             => 52;  # AFP 1.1
Readonly my $kFPAddAPPL                 => 53;  # AFP 1.1
Readonly my $kFPRemoveAPPL              => 54;  # AFP 1.1
Readonly my $kFPGetAPPL                 => 55;  # AFP 1.1
Readonly my $kFPAddComment              => 56;  # AFP 1.1
Readonly my $kFPRemoveComment           => 57;  # AFP 1.1
Readonly my $kFPGetComment              => 58;  # AFP 1.1
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
Readonly my $kFPAddIcon                 => 192; # AFP 1.1
# }}}1

Readonly our $kFPShortName          => 1;
Readonly our $kFPLongName           => 2;
Readonly our $kFPUTF8Name           => 3;   # AFP 3.0

Readonly our $kFPSoftCreate         => 0;
Readonly our $kFPHardCreate         => 0x80;

Readonly our $kFPStartEndFlag       => 0x80;
Readonly our $kFPLockUnlockFlag     => 1;

Readonly our $kFPAccessReadOnly     => 1;
Readonly our $kFPAccessWriteOnly    => 2;
Readonly our $kFPAccessReadWrite    => 3;

Readonly our $kFPResourceDataFlag   => 0x80;

# This class is only to be inherited. It uses virtual methods to talk to
# the server by whatever protocol the inheriting class is supposed to
# talk over, so we want this to be as generic as possible.
sub new { # {{{1
    my ($class, $host, $port) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s(host = '%s', port = '%s')},
      (caller 3)[3], $host, $port });

    my $obj = {};
    $obj->{logger} = $logger;
    bless $obj, $class;
    return $obj;
} # }}}1

# This is here so that Perl won't die of an "unknown method" if an
# inheriting class doesn't implement it. It's just a "virtual method"
# placeholder. It really shouldn't be called outside of a method anyway.
# Outside callers should be using the methods implemented for the AFP
# operations.
sub SendAFPMessage { # {{{1
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->error(sub { sprintf q{called %s() at line %d %s}, (caller 3)[3, 2],
      ((caller 3)[1] eq q/-/ ? 'on stdin' : 'in file ' . (caller 3)[1]) });
    croak('Do not call the base class SendAFPMessage method');
} # }}}1

sub SendAFPWrite { # {{{1
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->error(sub { sprintf q{called %s() at line %d %s}, (caller 3)[3, 2],
      ((caller 3)[1] eq q/-/ ? 'on stdin' : 'in file ' . (caller 3)[1]) });
    croak('Do not call the base class SendAFPWrite method');
} # }}}1

sub PackagePath { # {{{1
    my ($PathType, $Pathname, $NoEncType) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);

    $Pathname ||= q//;

    if ($PathType == $kFPShortName or $PathType == $kFPLongName) {
        return pack q{CC/a*}, $PathType, encode(q{MacRoman}, $Pathname);
    }
    elsif ($PathType == $kFPUTF8Name) {
        my $encodedPath = encode_utf8(decompose($Pathname));
        if ($NoEncType) {
            return pack q{CS>/a*}, $PathType, $encodedPath;
        }
        else {
            return pack q{CL>S>/a*}, $PathType, 0, $encodedPath;
        }
    }
    $logger->error(sub { sprintf q{Invalid path type %s; called from '%s', line %d},
      $PathType, (caller 4)[1, 2] });
    croak;
} # }}}1

sub FPAccess { # {{{1
    my($self, @options) = @_;

    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });
    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap      => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    $_[0] == 0
                },
            },
            default   => 0
        },
        UUID        => {
            type    => SCALAR,
            regex   => qr{\A[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}\z}ism,
        },
        ReqAccess   => {
            type        => SCALAR,
            callbacks   => {
                'valid access flags' => sub {
                    my $mask = ($KAUTH_VNODE_GENERIC_ALL_BITS |
                            $KAUTH_VNODE_WRITE_RIGHTS);
                    not $_[0] & ~$mask;
                },
            }
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                },
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $uuid;
    if (not $has_UUID) {
        croak('Module UUID was not available!');
    }
    UUID::parse($options{UUID}, $uuid);
    my $msg = pack q{CxS>L>S>a[16]L>a*}, $kFPAccess,
            @options{qw[VolumeID DirectoryID Bitmap]},
            $uuid, $options{ReqAccess},
            PackagePath(@options{qw[PathType Pathname]});
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddAPPL { # {{{1
    my($self, @options) = @_;

    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });
    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileCreator => { type => SCALAR },
        ApplTag     => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>L>a*}, $kFPAddAPPL,
            @options{qw[DTRefNum DirectoryID FileCreator ApplTag]},
            PackagePath(@options{qw[PathType Pathname]});
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddComment { # {{{1
    my($self, @options) = @_;

    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });
    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
        Comment     => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>a*x![s]C/a}, $kFPAddComment,
            @options{qw[DTRefNum DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]}),
            $options{Comment};
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPAddIcon { # {{{1
    my($self, @options) = @_;

    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });
    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileCreator => { type => SCALAR },
        FileType    => { type => SCALAR },
        IconType    => { type => SCALAR },
        IconTag     => { type => SCALAR },
        BitmapSize  => { type => SCALAR },
        IconBitmap  => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>CxL>S>}, $kFPAddIcon,
            @options{qw[DTRefNum FileCreator FileType IconType IconTag
            BitmapSize]};
    return $self->SendAFPWrite($msg, \$options{IconBitmap});
} # }}}1

sub _brlock_common { # {{{1
    my($self, $lf_mask, $rs_mask, $cmd, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 4)[3], Dumper({@options}) });
    my %options = validate(@options, {
        Flags       => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { not ~0x81 & $_[0] },
            }
        },
        OForkRefNum => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Offset      => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Length      => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    } );

    my $msg = pack sprintf(q{CCS%s%s}, $lf_mask, $lf_mask), $cmd,
            @options{qw[Flags OForkRefNum Offset Length]};
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc if $rc != $kFPNoErr;

    return($rc, unpack $rs_mask, $resp);
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPByteRangeLock { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_brlock_common($_[0], q{l>}, q{L>}, $kFPByteRangeLock, $_[1 .. $#_]));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPByteRangeLockExt { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_brlock_common($_[0], q{q>}, q{Q>}, $kFPByteRangeLockExt, $_[1 .. $#_]));
} # }}}1

sub _catsrch_common { # {{{1
    my ($self, $sl_pad, $sl_mask, $cmd, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 4)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ReqMatches          => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        CatalogPosition     => {
            type            => SCALAR,
            default         => "\0" x 16,
            callbacks       => {
                'valid position val' => sub {
                    length($_[0]) == 16
                },
            },
        },
        FileRsltBitmap      => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub { not ~0xFFFF & $_[0] },
            },
        },
        DirectoryRsltBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xBFFF & $_[0] },
            },
        },
        UTF8Name            => {
            type        => SCALAR,
            optional    => 1,
        },
        Attributes          => {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub {
                    my $mask = $kFPDeleteInhibitBit |
                               $kFPRenameInhibitBit |
                               $kFPWriteInhibitBit;
                    not $_[0] & ~$mask;
                }
            },
            optional    => 1,
        },
        ParentDirID         => {
            type      => SCALAR,
            optional  => 1,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                }
            },
        },
        CreateDate          => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        ModDate             => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        BackupDate          => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 9 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        FinderInfo          => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    return 1 if length($_[0]) != 32;
                },
            },
            optional    => 1,
        },
        LongName            => {
            type        => SCALAR,
            optional    => 1,
        },
        DataForkLen         => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        RsrcForkLen         => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        ExtDataForkLen      => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        ExtRsrcForkLen      => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        OffspringCount      => {
            type        => SCALAR | ARRAYREF,
            callbacks   => {
                'value check' => sub {
                    if (ref($_[0]) eq q{ARRAY}) {
                        return 0 if scalar(@{$_[0]}) != 2;
                        return 0 if not looks_like_number($_[0]->[0]);
                        looks_like_number($_[0]->[1]);
                    }
                    else {
                        looks_like_number($_[0]);
                    }
                },
            },
            optional    => 1,
        },
        MatchPartialNames   => {
            type        => SCALAR,
            optional    => 1,
        },
    });
    croak('VolumeID must be provided')
            if not exists $options{VolumeID};

    my(%Specification1, %Specification2);
    my @items = (
        {
            name   => 'Attributes',
            bitval => $kFPAttributeBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'ParentDirID',
            bitval => $kFPParentDirIDBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'CreateDate',
            bitval => $kFPCreateDateBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'ModDate',
            bitval => $kFPModDateBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'BackupDate',
            bitval => $kFPBackupDateBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'FinderInfo',
            bitval => $kFPFinderInfoBit,
            file   => 1,
            dir    => 1,
            both   => 1 },
        {
            name   => 'LongName',
            bitval => $kFPLongNameBit,
            file   => 1,
            dir    => 1,
            both   => 0 },
        {
            name   => 'OffspringCount',
            bitval => $kFPOffspringCountBit,
            file   => 0,
            dir    => 1,
            both   => 1 },
        {
            name   => 'DataForkLen',
            bitval => $kFPDataForkLenBit,
            file   => 1,
            dir    => 0,
            both   => 1 },
        {
            name   => 'RsrcForkLen',
            bitval => $kFPRsrcForkLenBit,
            file   => 1,
            dir    => 0,
            both   => 1 },
        {
            name   => 'ExtDataForkLen',
            bitval => $kFPExtDataForkLenBit,
            file   => 1,
            dir    => 0,
            both   => 1 },
        {
            name   => 'ExtRsrcForkLen',
            bitval => $kFPExtRsrcForkLenBit,
            file   => 1,
            dir    => 0,
            both   => 1 },
        {
            name   => 'UTF8Name',
            bitval => $kFPUTF8NameBit,
            file   => 1,
            dir    => 1,
            both   => 0 },
        {
            name   => 'MatchPartialNames',
            bitval => 1 << 31,
            file   => 1,
            dir    => 1,
            both   => 0 },
    );

    my $is_range = 0;
    my $Bitmap = 0;
    foreach my $item (@items) {
        if (exists $options{${$item}{name}}) {
            my $key = ${$item}{name};
            if ($options{FileRsltBitmap} == 0 and ${$item}{file}) {
                croak('Attempted to include file flag with no file bits set?');
            }
            if ($options{DirectoryRsltBitmap} == 0 and ${$item}{dir}) {
                croak('Attempted to include dir flag with no dir bits set?');
            }
            if (ref($options{${$item}{name}}) eq q{ARRAY}) {
                # if both is 0, it can only be in Specification1, i.e. it
                # can't be ranged
                if (not ${$item}{both}) {
                    carp(sprintf q{Option "%s" can't be in both search specs},
                      ${$item}{name});
                }
                $Specification1{$key} = $options{${$item}{name}}->[0];
                $Specification2{$key} = $options{${$item}{name}}->[1];
                $is_range = 1;
            }
            elsif (ref($options{${$item}{name}}) eq q{}) {
                $Specification1{$key} = $options{${$item}{name}};
                # only set it in Specification1, that's okay
                if (not ${$item}{both}) {
                    $Specification2{$key} = $options{${$item}{name}};
                }
            }
            $Bitmap |= ${$item}{bitval};
        }
    }

    my $is_dir = undef;
    if ($options{DirectoryRsltBitmap} == 0) {
        $is_dir = 0;
    }
    elsif ($options{FileRsltBitmap} == 0) {
        $is_dir = 1;
    }
    my $msg = pack q{CxS>L>x[4]a[16]S>S>L>}, $cmd,
            @options{qw[VolumeID ReqMatches CatalogPosition FileRsltBitmap
            DirectoryRsltBitmap]}, $Bitmap;
    my $params = PackSetParams($Bitmap, $is_dir, %Specification1);
    $msg .= pack sprintf(q{C%s/a}, $sl_pad), length($params), $params;
    if ($is_range == 1) {
        $params = PackSetParams($Bitmap, $is_dir, %Specification2);
        $msg .= pack q{Cx/a}, length($params), $params;
    }

    my($resp, $isfiledir, $paramdata, $results);
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;

    # this pack mask is hella wonky, but it should do what I need.
    (${$results = {}}{CatalogPosition}, my $filebmp, my $dirbmp, my @paramlist) =
        unpack sprintf(q{a[16]S>S>L>/(%s/(a![s]))}, $sl_mask), $resp;
    my $op = ${$results}{OffspringParameters} = [];
    while (($isfiledir, $paramdata) = splice @paramlist, 0, 2) {
        if ($isfiledir & 0x80) {
            push @{$op}, ParseDirParms($dirbmp, $paramdata);
        }
        else {
            push @{$op}, ParseFileParms($filebmp, $paramdata);
        }
    }
    return($rc, $results);
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPCatSearch { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_catsrch_common($_[0], q{x}, q{xCXXCx}, $kFPCatSearch, @_[1 .. $#_]));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPCatSearchExt { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_catsrch_common($_[0], q{}, q{x[s]CXXXS>xx}, $kFPCatSearchExt,
      @_[1 .. $#_]));
}  # }}}1

sub FPChangePassword { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($UAM, $UserName, $UserAuthInfo, $resp_r) =
      validate_pos(@options,
        { type => SCALAR },
        { type => SCALAR },
        { type => SCALAR, optional => 1, default => q{} },
        {
            type      => SCALARREF,
            optional  => 1,
            default   => *bar{SCALAR}
        },
    );

    my $msg = pack q{CxC/a*x![s]C/a*x![s]a*}, $kFPChangePassword, $UAM,
            $UserName, $UserAuthInfo;
    return $self->SendAFPMessage($msg, $resp_r, 1);
} # }}}1

sub FPCloseDir { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $DirectoryID) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack q{CxS>L>}, $kFPCloseDir, $VolumeID,
            $DirectoryID);
} # }}}1

sub FPCloseDT { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($DTRefNum) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack q{CxS>}, $kFPCloseDT, $DTRefNum);
} # }}}1

sub FPCloseFork { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($OForkRefNum) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>}, $kFPCloseFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPCloseVol { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>}, $kFPCloseVol, $VolumeID),
            undef, 1);
} # }}}1

sub FPCopyFile { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        SourceVolumeID      => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourceDirectoryID   => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DestVolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DestDirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
        NewType             => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        NewName             => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>L>a*a*a*}, $kFPCopyFile,
            @options{qw[SourceVolumeID SourceDirectoryID DestVolumeID
            DestDirectoryID]},
            PackagePath(@options{qw[SourcePathType SourcePathname]}),
            PackagePath(@options{qw[DestPathType DestPathname]}),
            PackagePath(@options{qw[NewType NewName]});
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPCreateDir { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type      => SCALAR,
            callbacks => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>L>a*}, $kFPCreateDir,
            @options{qw[VolumeID DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]})), \$resp, 1);
    if ($rc == $kFPNoErr and wantarray) {
        return($rc, unpack q{L>}, $resp);
    }
    return $rc;
} # }}}1

sub FPCreateFile { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID       => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType       => {
            type       => SCALAR,
            callbacks  => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname       => { type => SCALAR },
        Flag           => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    not ~0x80 & $_[0]
                },
            },
            default   => 0,
        },
    } );

    return $self->SendAFPMessage(pack(q{CCS>L>a*}, $kFPCreateFile,
            @options{qw[Flag VolumeID DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]})), undef, 1);
} # }}}1

sub FPCreateID { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $msg = pack q{CxS>L>a*}, $kFPCreateID,
            @options{qw[VolumeID DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]});
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != $kFPNoErr;
    if (not wantarray) {
        croak('Need to accept returned list');
    }
    return($rc, unpack q{L>}, $resp);
} # }}}1

sub FPDelete { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $DirectoryID, $PathType, $Pathname) =
      validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            }
        },
        {
            type       => SCALAR,
            callbacks  => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName ||
                    $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        { type => SCALAR },
    );

    return $self->SendAFPMessage(pack(q{CxS>L>a*}, $kFPDelete, $VolumeID,
            $DirectoryID, PackagePath($PathType, $Pathname)), undef, 1);
} # }}}1

sub FPDeleteID { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $FileID) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack q{CxS>L>}, $kFPDeleteID, $VolumeID,
            $FileID);
} # }}}1

sub FPDisconnectOldSession { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    # FIXME: Maybe validate these better?
    my($Type, $Token) = validate_pos(@options,
        { type => SCALAR },
        { type => SCALAR },
    );

    return $self->SendAFPMessage(pack q{CxS>L>/a}, $kFPDisconnectOldSession,
            $Type, $Token);
} # }}}1

# since all 3 enumerate calls are... pretty similar, let's wrap all 3 in a
# common subroutine, to eliminate duplication
##no critic qw(ProhibitManyArgs)
sub _enum_common { # {{{1
    my($self, $sl_type, $fd_pad, $si_type, $mr_type, $cmd, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 4)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFFF & $_[0] },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xBFFF & $_[0] },
            },
        },
        ReqCount        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        StartIndex      => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        MaxReplySize    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );
    croak('Must accept array return') if not wantarray;

    my $msg = pack sprintf(q{CxS>L>S>S>S>%s%sa*}, $si_type, $mr_type), $cmd,
            @options{qw[VolumeID DirectoryID FileBitmap DirectoryBitmap
            ReqCount StartIndex MaxReplySize]},
            PackagePath(@options{qw[PathType Pathname]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    my($FileBitmap, $DirectoryBitmap) = unpack q{S>S>}, $resp;
    my @results = map {
        # first byte indicates entry length, next byte contains the 
        # isFileDir bit
        my ($IsFileDir, $OffspringParameters) = unpack sprintf(q{%sa*}, $fd_pad), $_;
        if ($IsFileDir == 0x80) {
            # This child is a directory
            ParseDirParms($DirectoryBitmap, $OffspringParameters);
        }
        else {
            # This child is a file
            ParseFileParms($FileBitmap, $OffspringParameters);
        }
    } unpack sprintf(q{x[s]x[s]S>/(%s/a)}, $sl_type), $resp;
    return($rc, [@results]);
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPEnumerate { # {{{1
    croak('Must accept array return') if not wantarray;
    return(_enum_common($_[0], q{CX}, q{xC}, q{S>}, q{S>}, $kFPEnumerate,
      @_[1 .. $#_]));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPEnumerateExt { # {{{1
    croak('Must accept array return') if not wantarray;
    return(_enum_common($_[0], q{S>X[s]}, q{x[2]Cx}, q{S>}, q{S>},
      $kFPEnumerateExt, @_[1 .. $#_]));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPEnumerateExt2 { # {{{1
    croak('Must accept array return') if not wantarray;
    return(_enum_common($_[0], q{S>X[s]}, q{x[2]Cx}, q{L>}, q{L>},
      $kFPEnumerateExt2, @_[1 .. $#_]));
} # }}}1

sub FPExchangeFiles { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourceDirectoryID   => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DestDirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>a*a*}, $kFPExchangeFiles,
            @options{qw[VolumeID SourceDirectoryID DestDirectoryID]},
            PackagePath(@options{qw[SourcePathType SourcePathname]}),
            PackagePath(@options{qw[DestPathType DestPathname]});
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPFlush { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>}, $kFPFlush, $VolumeID),
            undef, 1);
} # }}}1

sub FPFlushFork { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($OForkRefNum) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>}, $kFPFlushFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub FPGetACL { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap          => {
            type        => SCALAR,
            default     => $kFileSec_ACL,
            callbacks   => {
                'valid flags' => sub {
                    my $mask = $kFileSec_UUID | $kFileSec_GRPUUID |
                            $kFileSec_ACL;
                    not $_[0] & ~$mask;
                },
            }
        },
        MaxReplySize    => {
            type      => SCALAR,
            default   => 0,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                     $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                     $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>L>a*}, $kFPGetACL,
            @options{qw[VolumeID DirectoryID Bitmap MaxReplySize]},
            PackagePath(@options{qw[PathType Pathname]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    my %rvals;
    ($rvals{Bitmap}, $resp) = unpack q{S>a*}, $resp;

    if (not $has_UUID) {
        croak('Module UUID was not available!');
    }

    if ($rvals{Bitmap} & $kFileSec_UUID) {
        ($rvals{UUID}, $resp) = unpack q{a[16]a*}, $resp;
        UUID::unparse($rvals{UUID}, $rvals{UUID});
    }

    if ($rvals{Bitmap} & $kFileSec_GRPUUID) {
        ($rvals{GRPUUID}, $resp) = unpack q{a[16]a*}, $resp;
        UUID::unparse($rvals{GRPUUID}, $rvals{GRPUUID});
    }

    if ($rvals{Bitmap} & $kFileSec_ACL) {
        ($rvals{acl_flags}, my @entries) = unpack q{x[l]L>X[ll]L>x[l]/(a[16]L>L>)}, $resp;
        my(@acl_ace, $ace);
        while (@{$ace = {}}{qw(ace_applicable ace_flags ace_rights)} =
          splice @entries, 0, 3) {
            UUID::unparse(${$ace}{ace_applicable}, ${$ace}{ace_applicable});
            push @acl_ace, $ace;
        }
        $rvals{acl_ace} = [ @acl_ace ];
    }
    return($rc, %rvals);
} # }}}1

sub FPGetAPPL { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileCreator => { type => SCALAR },
        APPLIndex   => { type => SCALAR },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { not ~0xFFFF & $_[0] },
            },
        },
    } );

    my $msg = pack q{CxS>L>S>S>}, $kFPGetAPPL,
            @options{qw[DTRefNum FileCreator APPLIndex Bitmap]};

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    my($Bitmap_n, $APPLTag, $data) = unpack q{S>L>a*}, $resp;
    my $info = ParseFileParms($Bitmap_n, $data);
    my %rvals = (
                  Bitmap            => $Bitmap_n,
                  APPLTag           => $APPLTag,
                  FileParameters    => $info,
                );
    return($rc, %rvals);
} # }}}1

sub FPGetAuthMethods { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Flags, $PathType, $Pathname, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                # FIXME: Can we validate this better?
                'valid flags' => sub { $_[0] == 0 }
            }
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        { type => SCALAR },
        { type => SCALARREF },
    );

    my $msg = pack q{CxCa*}, $kFPGetAuthMethods, $Flags,
            PackagePath($PathType, $Pathname);
    my($resp, @UAMStrings);
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    ($Flags, @UAMStrings) = unpack q{CC/(C/a)}, $resp;
    ${$resp_r} = { Flags => $Flags, UAMStrings => [ @UAMStrings ] };
    return $rc;
} # }}}1

sub FPGetComment { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                     $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                     $_[0] == $kFPUTF8Name
                },
            }
        },
        Pathname    => { type => SCALAR },
    } );
    if (not wantarray) {
        croak('Need to accept returned list');
    }

    my $msg = pack q{CxS>L>a*}, $kFPGetComment,
            @options{qw[DTRefNum DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    return($rc, unpack q{C/a}, $resp);
} # }}}1

sub FPGetExtAttr { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub {
                    $_[0] == $kXAttrNoFollow || $_[0] == 0
                },
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
        MaxReplySize    => {
            type      => SCALAR,
            default   => 0,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
        Name            => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>Q>Q>L>a*x![s]S>/a*}, $kFPGetExtAttr,
            @options{qw[VolumeID DirectoryID Bitmap Offset ReqCount
            MaxReplySize]},
            PackagePath(@options{qw[PathType Pathname]}),
            encode_utf8(decompose($options{Name}));
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    my %rvals;
    if ($options{MaxReplySize} > 0) {
        @rvals{qw[Bitmap AttributeData]} = unpack q{S>L>/a*}, $resp;
    }
    else {
        @rvals{qw[Bitmap DataLength]} = unpack q{S>L>}, $resp;
    }
    return($rc, %rvals);
} # }}}1

sub FPGetFileDirParms { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileBitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFFF & $_[0] },
            },
        },
        DirectoryBitmap => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xBFFF & $_[0] },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>S>a*}, $kFPGetFileDirParms,
            @options{qw[VolumeID DirectoryID FileBitmap DirectoryBitmap]},
            PackagePath(@options{qw[PathType Pathname]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    return($rc, ParseFileDirParms($resp));
} # }}}1

sub FPGetForkParms { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($OForkRefNum, $Bitmap, $resp_r) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub {
                    not ~0xFFFF & $_[0]
                }
            }
        },
        { type => SCALARREF },
    );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>S>}, $kFPGetForkParms,
            $OForkRefNum, $Bitmap), \$resp);
    return $rc if $rc != $kFPNoErr;
    ${$resp_r} = ParseFileParms(unpack q{S>a*}, $resp);
    return $rc;
} # }}}1

sub FPGetIcon { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileCreator => { type => SCALAR },
        FileType    => { type => SCALAR },
        IconType    => { type => SCALAR },
        Length      => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>CxS>}, $kFPGetIcon,
            @options{qw[DTRefNum FileCreator FileType IconType Length]};
    croak('Need to accept returned list') if not wantarray;
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, $rdata);
} # }}}1

sub FPGetIconInfo { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($DTRefNum, $FileCreator, $IconIndex, $resp_r) =
      validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        { type => SCALAR },
        { type => SCALAR },
        { type => SCALARREF },
    );

    my $resp;
    my $msg = pack q{CxS>L>S>}, $kFPGetIconInfo, $DTRefNum, $FileCreator,
            $IconIndex;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != $kFPNoErr;
    @{${$resp_r} = {}}{qw[IconTag FileType IconType Size]} =
            unpack q{L>L>CxS>}, $resp;
    return $rc;
} # }}}1

sub FPGetSessionToken { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Type, $timeStamp, $ID, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid type' => sub {
                    $_[0] >= $kLoginWithoutID &&
                        $_[0] <= $kGetKerberosSessionKey
                }
            }
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
            optional  => 1,
        },
        { type => SCALAR, optional => 1, default => q{} },
        { type => SCALARREF },
    );

    my $resp;
    my $pack_mask = q{CxS>L>};
    my @params = ($kFPGetSessionToken, $Type, length $ID);
    if (defined $timeStamp) {
        if (looks_like_number($timeStamp)) {
            $pack_mask .= q{L>};
        } else {
            $pack_mask .= q{a*};
        }
        push @params, $timeStamp;
    }
    $pack_mask .= q{a*};
    push @params, $ID;

    my $msg = pack $pack_mask, @params;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    if ($rc == $kFPNoErr) {
        ${$resp_r} = unpack q{L>/a}, $resp;
    }
    return $rc;
} # }}}1

sub FPGetSrvrInfo { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($resp_r) = validate_pos(@options, { type => SCALARREF });

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{Cx}, $kFPGetSrvrInfo), \$resp);
    # If the response was not $kFPNoErr, the info block will not be present.
    return $rc if $rc != $kFPNoErr;

    ${$resp_r} = ParseSrvrInfo($resp);
    return $rc;
} # }}}1

sub FPGetSrvrMsg { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

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
                'valid bitmap' => sub { not ~0x3 & $_[0] }
            }
        },
        { type => SCALARREF },
    );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>S>}, $kFPGetSrvrMsg, $MessageType,
            $MessageBitmap), \$resp);
    return $rc if $rc != $kFPNoErr;
    my ($Length, $ServerMessage);
    # FIXME: Not sure if this is quite right...
    if ($MessageBitmap & 0x2) { # bit 1; means send message as UTF8
        ($Length, $MessageType, $MessageBitmap, $ServerMessage) =
                unpack q{S>S>S>S>/a}, $resp;
        $ServerMessage = compose(decode_utf8($ServerMessage));
    }
    else { # not UTF8, just a plain pstring (?)
        ($MessageType, $MessageBitmap, $ServerMessage) =
                unpack q{S>S>C/a}, $resp;
        $Length = length $ServerMessage;
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
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($resp_r) = validate_pos(@options, { type => SCALARREF });

    my($resp, $data);
    my $rc = $self->SendAFPMessage(pack(q{Cx}, $kFPGetSrvrParms), \$resp);
    # If the response was not $kFPNoErr, the info block will not be present.
    return $rc if $rc != $kFPNoErr;

    my ($time, @volinfo) = unpack q{l>C/(CC/a)}, $resp;
    # AFP does not express times since 1 Jan 1970 00:00 GMT, but since 
    # 1 Jan 2000 00:00 GMT (I think GMT, anyway). Good call, Apple...
    @{$data = {}}{qw(ServerTime Volumes)} =
      ($time + globalTimeOffset, []);
    my($flags, $volname, $volinfo);
    while (($flags, $volname) = splice @volinfo, 0, 2) {
        if (Net::AFP::Versions::CompareByVersionNum($self, 3, 0,
                $kFPVerAtLeast)) {
            $volname = decode_utf8($volname);
        }
        else {
            $volname = decode('MacRoman', $volname);
        }
        # The documentation from Apple says "HasUNIXPrivs" is the high
        # bit; ethereal seems to think it's the second bit, not the high
        # bit. I'll have to see how to turn that on somewhere to find out.
        # Also, looks like the HasUNIXPrivs bit is gone as of AFP 3.2...
        $volinfo = { HasPassword    => $flags & 0x80,
                     HasConfigInfo  => $flags & 0x01,
                     VolName        => $volname };
        if (Net::AFP::Versions::CompareByVersionNum($self, 3, 2,
          $kFPVerAtLeast)) {
            ${$volinfo}{HasUNIXPrivs} = 1;
        }
        # I _think_ that was the right bit...
        elsif ($flags & 0x02) {
            ${$volinfo}{HasUNIXPrivs} = 1;
        }
        else {
            ${$volinfo}{HasUNIXPrivs} = 0;
        }

        push @{${$data}{Volumes}}, $volinfo;
    }
    ${$resp_r} = $data;
    return $rc;
} # }}}1

sub FPGetUserInfo { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Flags, $UserID, $Bitmap, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid type' => sub { not ~0x1 & $_[0] }
            }
        },
        { type => SCALAR },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub { not ~0x7 & $_[0] }
            }
        },
        { type => SCALARREF },
    );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CCL>S>}, $kFPGetUserInfo, $Flags,
            $UserID, $Bitmap), \$resp);

    return $rc if $rc != $kFPNoErr;

    my $rbmp = unpack q{S>}, $resp;
    my $offset = 2;
    ${$resp_r} = {};
    if ($rbmp & 0x1) { # Get User ID bit
        ${$resp_r}->{UserID} = unpack sprintf(q{x[%d]L>}, $offset), $resp;
        $offset += 4;
    }
    if ($rbmp & 0x2) {
        if (Net::AFP::Versions::CompareByVersionNum($self, 2, 1,
                $kFPVerAtLeast)) {
            if (exists ${$resp_r}->{UserID}) {
                ${$resp_r}->{PrimaryGroupID} = ${$resp_r}->{UserID};
            }
        }
        else {
            ${$resp_r}->{PrimaryGroupID} =
                    unpack sprintf(q{x[%d]L>}, $offset), $resp;
            $offset += 4;
        }
    }
    if ($rbmp & 0x4) {
        if (not $has_UUID) {
            croak('Module UUID was not available!');
        }

        UUID::unparse(unpack(sprintf(q{x[%d]a[16]}, $offset), $resp),
          ${$resp_r}->{UUID});
        $offset += 16;
    }

    return $rc;
} # }}}1

sub FPGetVolParms { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $Bitmap, $resp_r) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFF & $_[0] }
            }
        },
        { type => SCALARREF },
    );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>S>}, $kFPGetVolParms, $VolumeID,
            $Bitmap), \$resp);
    return($rc) if $rc != $kFPNoErr;
    ${$resp_r} = ParseVolParms($resp, $self);
    return $rc;
} # }}}1

sub FPListExtAttrs { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub { $_[0] == $kXAttrNoFollow },
            }
        },
        ReqCount        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        StartIndex      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid index' => sub { $_[0] == 0 },
            },
        },
        MaxReplySize    => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>S>L>L>a*}, $kFPListExtAttrs,
            @options{qw[VolumeID DirectoryID Bitmap ReqCount StartIndex
            MaxReplySize]},
            PackagePath(@options{qw[PathType Pathname]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    my %rvals;
    if ($options{MaxReplySize} > 0) {
        my $names;
        ($rvals{Bitmap}, $names) = unpack q{S>L>/a*}, $resp;
        $rvals{AttributeNames} =
                [ map { compose(decode_utf8($_)) } unpack q{(Z*)*}, $names ];
    }
    else {
        @rvals{qw[Bitmap DataLength]} = unpack q{S>L>}, $resp;
    }
    return($rc, %rvals);
} # }}}1

sub FPLogin { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($AFPVersion, $UAM, $UserAuthInfo) = validate_pos(@options,
        { type => SCALAR },
        { type => SCALAR },
        { type => SCALAR, optional => 1, default => q{} }
    );

    my $msg = pack q{CC/a*C/a*a*}, $kFPLogin, $AFPVersion, $UAM,
            $UserAuthInfo;
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);

    croak('Need to accept returned list') if not wantarray;
    if ($rc == $kFPAuthContinue and length($resp) >= 2) {
        $rvals{ID} = unpack q{S>}, $resp;
        if (length($resp) > 2) {
            $rvals{UserAuthInfo} = substr $resp, 2;
        }
    }
    return($rc, %rvals);
} # }}}1

sub FPLoginCont { # {{{1
    my ($self, @options) = @_;

    my($ID, $UserAuthInfo, $resp_r) = validate_pos(@options,
        { type => SCALAR, optional => 1 },
        { type => SCALAR, optional => 1, default => q{} },
        {
            type      => SCALARREF,
            optional  => 1,
            default   => *foo{SCALAR},
        }
    );
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([$ID, unpack(q{H*}, $UserAuthInfo), $resp_r]) });

    my($resp, $rc);
    # Unlike FPLogin, the pad byte actually does need to be there.
    if (defined $ID) {
        $rc = $self->SendAFPMessage(pack(q{CxS>a*}, $kFPLoginCont, $ID,
                $UserAuthInfo), \$resp);
    }
    else {
        $rc = $self->SendAFPMessage(pack(q{Cxa*}, $kFPLoginCont,
                $UserAuthInfo), \$resp);
    }

    if (($rc == $kFPAuthContinue || $rc == $kFPNoErr)
            && defined $resp) {
        ${$resp_r} = {};
        my $offset = 0;
        if ($rc == $kFPAuthContinue) {
            ${$resp_r}->{ID} = unpack q{S>}, $resp;
            $offset = 2;
        }
        if (length($resp) > $offset) {
            ${$resp_r}->{UserAuthInfo} = substr $resp, $offset;
        }
    }
    return $rc;
} # }}}1

sub FPLoginExt { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

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
            default     => $kFPUTF8Name,
            callbacks   => {
                'valid type flag' => sub { $_[0] == $kFPUTF8Name },
            }
        },
        UserName        => { type => SCALAR },
        # Documentation doesn't say this has to always be UTF8, but it's a
        # safe choice, and generally we don't give a damn
        PathType        => {
            type        => SCALAR,
            default     => $kFPUTF8Name,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
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

    my $msg = pack q{CxS>C/a*C/a*a*a*x![s]a*}, $kFPLoginExt,
            @options{qw[Flags AFPVersion UAM]},
            PackagePath(@options{qw[UserNameType UserName]}, 1),
            PackagePath(@options{qw[PathType Pathname]}, 1),
            $options{UserAuthInfo};
    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp);

    croak('Need to accept returned list') if not wantarray;
    if ($rc == $kFPAuthContinue and length($resp) >= 2) {
        $rvals{ID} = unpack q{S>}, $resp;
        if (length($resp) > 2) {
            $rvals{UserAuthInfo} = substr $resp, 2;
        }
    }
    return($rc, %rvals);
} # }}}1

sub FPLogout { # {{{1
    my ($self) = @_;
    $self->{logger}->debug(sub { sprintf 'called %s()', (caller 3)[3] });

    return $self->SendAFPMessage(pack q{Cx}, $kFPLogout);
} # }}}1

sub FPMapID { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Subfunction, $ID, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid subfunction' => sub {
                    $_[0] >= $kUserIDToName &&
                      $_[0] <= $kGroupUUIDToUTF8Name
                }
            }
        },
        { type => SCALAR },
        { type => SCALARREF },
    );

    my $resp;
    my $pack_mask = q{CC};
    my @pack_args = ($kFPMapID, $Subfunction);
    if ($Subfunction == $kUserUUIDToUTF8Name ||
            $Subfunction == $kGroupUUIDToUTF8Name) {
        if (not $has_UUID) {
            croak('Module UUID was not available!');
        }

        $pack_mask .= q{a[16]};
        UUID::parse($ID, $ID);
    }
    else {
        $pack_mask .= q{N};
    }
    push @pack_args, $ID;
    my $msg = pack $pack_mask, @pack_args;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    if ($Subfunction == $kUserUUIDToUTF8Name ||
            $Subfunction == $kGroupUUIDToUTF8Name) {
        @{${$resp_r} = {}}{qw[Bitmap NumericID UTF8Name]} =
                unpack q{L>L>S>/a}, $resp;
        ${${$resp_r}}{UTF8Name} =
                compose(decode_utf8(${$resp_r}->{UTF8Name}));
    }
    elsif ($Subfunction == $kUserIDToUTF8Name ||
            $Subfunction == $kGroupIDToUTF8Name) {
        (${$resp_r}) = compose(decode_utf8(unpack q{C/a}, $resp));
    }
    else {
        (${$resp_r}) = decode(q{MacRoman}, unpack q{C/a}, $resp);
    }
    return $rc;
} # }}}1

sub FPMapName { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Subfunction, $Name, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid subfunction' => sub {
                    $_[0] >= $kNameToUserID &&
                            $_[0] <= $kUTF8NameToGroupUUID
                }
            }
        },
        { type => SCALAR },
        { type => SCALARREF },
    );

    my $resp;
    my $pack_mask = q{CC};
    if ($Subfunction == $kUTF8NameToUserUUID ||
            $Subfunction == $kUTF8NameToGroupUUID) {
        $pack_mask .= q{S>/a*};
        $Name = encode_utf8(decompose($Name));
    }
    else {
        $pack_mask .= q{C/a*};
        if ($Subfunction == $kUTF8NameToUserID ||
                $Subfunction == $kUTF8NameToGroupID) {
            $Name = encode_utf8(decompose($Name));
        }
        else {
            $Name = encode(q{MacRoman}, $Name);
        }
    }
    my $msg = pack $pack_mask, $kFPMapName, $Subfunction, $Name;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return $rc if $rc != $kFPNoErr;
    if ($Subfunction == $kUTF8NameToUserUUID ||
            $Subfunction == $kUTF8NameToGroupUUID) {
        if (not $has_UUID) {
            croak('Module UUID was not available!');
        }

        # HACK: For some reason $resp's contents aren't visible until it
        # gets accessed?
        if (length $resp) { }
        UUID::unparse($resp, ${$resp_r});
    }
    else {
        (${$resp_r}) = unpack q{L>}, $resp;
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
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourceDirectoryID   => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DestDirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        SourcePathType      => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        SourcePathname      => { type => SCALAR },
        DestPathType        => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        DestPathname        => { type => SCALAR },
        NewType             => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        NewName             => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>a*a*a*}, $kFPMoveAndRename,
            @options{qw[VolumeID SourceDirectoryID DestDirectoryID]},
            PackagePath(@options{qw[SourcePathType SourcePathname]}),
            PackagePath(@options{qw[DestPathType DestPathname]}),
            PackagePath(@options{qw[NewType NewName]});
    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc;
} # }}}1

sub FPOpenDir { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>L>a*}, $kFPOpenDir,
            @options{qw[VolumeID DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]})), \$resp);
    return $rc if $rc != $kFPNoErr;
    croak('Need to accept returned list') if not wantarray;
    return($rc, unpack q{L>}, $resp);
} # }}}1

sub FPOpenDT { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $resp_r) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        { type => SCALARREF },
    );

    my $resp;
    my $rc = $self->SendAFPMessage(pack(q{CxS>}, $kFPOpenDT, $VolumeID),
            \$resp);
    return $rc if $rc != $kFPNoErr;
    (${$resp_r}) = unpack q{S>}, $resp;
    return $rc;
} # }}}1

sub FPOpenFork { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        Flag        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flag bits' => sub { not ~0x80 & $_[0] },
            },
        },
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFFF & $_[0] },
            },
        },
        AccessMode  => {
            type        => SCALAR,
            callbacks   => {
                'valid access mode' => sub { not ~0x33 & $_[0] },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack q{CCS>L>S>S>a*}, $kFPOpenFork,
            @options{qw[Flag VolumeID DirectoryID Bitmap AccessMode]},
            PackagePath(@options{qw[PathType Pathname]});

    my $resp;
    my %rvals;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    croak('Need to accept returned list') if not wantarray;
    if ($rc == $kFPNoErr) {
        my ($rBitmap, $OForkRefNum, $FileParameters) = unpack q{S>S>a*}, $resp;
        %rvals = %{ ParseFileParms($rBitmap, $FileParameters) };
        $rvals{OForkRefNum} = $OForkRefNum;
    }
    return($rc, %rvals);
} # }}}1

sub FPOpenVol { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Bitmap, $VolumeName, $Password, $resp_r) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFF & $_[0] }
            }
        },
        { type => SCALAR },
        { type => SCALAR | UNDEF, optional => 1, default => q{} },
        { type => SCALARREF },
    );

    # Make sure the VolID bit is set, because it's kind of necessary.
    $Bitmap |= $kFPVolIDBit;

    if (Net::AFP::Versions::CompareByVersionNum($self, 3, 0,
            $kFPVerAtLeast)) {
        $VolumeName = encode_utf8($VolumeName);
    }
    else {
        $VolumeName = encode('MacRoman', $VolumeName);
    }

    my $PackPattern = q{CxS>Ca*};
    my @PackArgs = ($kFPOpenVol, $Bitmap, length($VolumeName), $VolumeName);
    # Only append a password if one was provided. If not, we don't provide
    # it.
    if (defined $Password) {
        $PackPattern .= q{x![s]Z8};
        push @PackArgs, $Password;
    }
    my $msg = pack $PackPattern, @PackArgs;

    my $resp;
    my $rc = $self->SendAFPMessage($msg, \$resp, 1);
    return $rc if $rc != $kFPNoErr;
    ${$resp_r} = ParseVolParms($resp, $self);
    return $rc;
} # }}}1

sub _read_common { # {{{1
    my($self, $extraopts, $optnames, $mask, $cmd, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 4)[3], Dumper({@options}) });

    my %options = validate(@options, {
        OForkRefNum => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Offset      => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ReqCount    => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        (defined $extraopts and ref($extraopts) eq 'HASH') ? %{$extraopts} : (),
    } );

    my $msg = pack sprintf(q{CxS>%s}, $mask), $cmd,
            @options{qw[OForkRefNum Offset ReqCount]},
            (defined $optnames and ref($optnames) eq 'ARRAY') ? @options{@{$optnames}} : ();

    croak('Need to accept returned list') if not wantarray;
    my $rdata;
    my $rc = $self->SendAFPMessage($msg, \$rdata);
    return($rc, \$rdata);
} # }}}1

sub FPRead { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_read_common($_[0], {
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
    }, [qw(NewLineMask NewLineChar)], q{L>L>CC}, $kFPRead, @_[1 .. $#_]));
} # }}}1

sub FPReadExt { # {{{1
    croak('Need to accept returned list') if not wantarray;
    return(_read_common($_[0], undef, undef, q{Q>Q>}, $kFPReadExt, @_[1 .. $#_]));
} # }}}1

sub FPRemoveAPPL { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        DTRefNum    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FileCreator => { type => SCALAR },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>L>a*}, $kFPRemoveAPPL,
            @options{qw[DTRefNum DirectoryID FileCreator]},
            PackagePath(@options{qw[PathType Pathname]});
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPRemoveComment { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($DTRefNum, $DirectoryID, $PathType, $Pathname) =
      validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName ||
                    $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            }
        },
        { type => SCALAR }
    );

    my $msg = pack q{CxS>L>a*}, $kFPRemoveComment, $DTRefNum, $DirectoryID,
            PackagePath($PathType, $Pathname);
    return $self->SendAFPMessage($msg);
} # }}}1

sub FPRemoveExtAttr { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap      => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub {
                    $_[0] == $kXAttrNoFollow || $_[0] == 0
                },
            }
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                },
            }
        },
        Pathname    => { type => SCALAR },
        Name        => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>a*x![s]S>/a*}, $kFPRemoveExtAttr,
            @options{qw[VolumeID DirectoryID Bitmap]},
            PackagePath(@options{qw[PathType Pathname]}),
            encode_utf8(decompose($options{Name}));
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPRename { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname    => { type => SCALAR },
        NewType     => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        NewName     => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>a*a*}, $kFPRename,
            @options{qw[VolumeID DirectoryID]},
            PackagePath(@options{qw[PathType Pathname]}),
            PackagePath(@options{qw[NewType NewName]});
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPResolveID { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $FileID, $Bitmap, $resp_r) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        { type => SCALAR },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub { not ~0xFFFF & $_[0] }
            }
        },
        { type => SCALARREF },
    );

    my $resp;
    my $msg = pack q{CxS>L>S>}, $kFPResolveID, $VolumeID, $FileID, $Bitmap;
    my $rc = $self->SendAFPMessage($msg, \$resp);
    return($rc) if $rc != $kFPNoErr;
    my($Bitmap_n, $data) = unpack q{S>a*}, $resp;
    ${$resp_r} = {
                   Bitmap               => $Bitmap_n,
                   RequestedParameters  => ParseFileParms($Bitmap_n, $data),
                 };
    return $rc;
} # }}}1

sub FPSetACL { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID    => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap      => {
            type        => SCALAR,
            default     => $kFileSec_ACL,
            callbacks   => {
                'valid flags' => sub {
                    my $mask = $kFileSec_UUID | $kFileSec_GRPUUID |
                            $kFileSec_ACL | $kFileSec_REMOVEACL |
                            $kFileSec_Inherit;
                    not $_[0] & ~$mask;
                },
            }
        },
        PathType    => {
            type        => SCALAR,
            callbacks   => {
                'valid path type' => sub {
                     $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                     $_[0] == $kFPUTF8Name
                }
            }
        },
        Pathname    => { type => SCALAR },
        UUID        => {
            type     => SCALAR,
            regex    => qr{\A[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}\z}ism,
            optional => 1,
        },
        GRPUUID     => {
            type     => SCALAR,
            regex    => qr{\A[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}\z}ism,
            optional => 1,
        },
        acl_ace     => { type => ARRAYREF, optional => 1 },
        acl_flags   => { type => SCALAR, optional => 1 },
    } );

    my $msg = pack q{CxS>L>S>a*x![s]}, $kFPSetACL,
            @options{qw[VolumeID DirectoryID Bitmap]},
            PackagePath(@options{qw[PathType Pathname]});

    if (not $has_UUID) {
        croak('Module UUID was not available!');
    }
    my $tmp;

    if ($options{Bitmap} & $kFileSec_UUID) {
        croak('UUID must be provided')
                if not exists $options{UUID};
        UUID::parse($options{UUID}, $tmp);
        $msg .= $tmp;
    }
    if ($options{Bitmap} & $kFileSec_GRPUUID) {
        croak('GRPUUID must be provided')
                if not exists $options{GRPUUID};
        UUID::parse($options{GRPUUID}, $tmp);
        $msg .= $tmp;
    }
    if ($options{Bitmap} & $kFileSec_ACL) {
        croak('acl_ace must be provided')
                if not exists $options{acl_ace};
        croak('acl_flags must be provided')
                if not exists $options{acl_flags};
        my @ace_list = map {
            UUID::parse(${$_}{ace_applicable}, $tmp);
            pack q{a[16]L>L>}, $tmp, @{$_}{qw[ace_flags ace_rights]};
        } @{$options{acl_ace}};
        $msg .= pack sprintf(q{L>L>(a*)[%d]}, scalar @ace_list), scalar(@ace_list),
            $options{acl_flags}, @ace_list;
    }

    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetDirParms { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID         => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = $kFPAttributeBit | $kFPCreateDateBit |
                            $kFPModDateBit | $kFPBackupDateBit |
                            $kFPFinderInfoBit | $kFPOwnerIDBit |
                            $kFPGroupIDBit | $kFPAccessRightsBit |
                            $kFPUnixPrivsBit;
                    not ~$mask & $_[0];
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attributes          => { type => SCALAR, optional => 1 },
        CreateDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ModDate             => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        BackupDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FinderInfo          => { type => SCALAR, optional => 1 },
        OwnerID             => { type => SCALAR, optional => 1 },
        GroupID             => { type => SCALAR, optional => 1 },
        AccessRights        => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, 1, %options);
    return $kFPParamErr if not defined $ParamsBlock;

    my $msg = pack q{CxS>L>S>a*x![s]a*}, $kFPSetDirParms,
            @options{qw[VolumeID DirectoryID Bitmap]},
            PackagePath(@options{qw[PathType Pathname]}),
            $ParamsBlock;
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetExtAttr { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID        => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID     => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap          => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flags' => sub {
                    my $mask = $kXAttrNoFollow | $kXAttrCreate |
                               $kXAttrReplace;
                    not ~$mask & $_[0];
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
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                },
            }
        },
        Pathname        => { type => SCALAR },
        Name            => { type => SCALAR },
        AttributeData   => { type => SCALAR },
    } );

    my $msg = pack q{CxS>L>S>Q>a*x![s]S>/a*L>/a*}, $kFPSetExtAttr,
            @options{qw[VolumeID DirectoryID Bitmap Offset]},
            PackagePath(@options{qw[PathType Pathname]}),
            encode_utf8(decompose($options{Name})),
            $options{AttributeData};
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetFileDirParms { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID         => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = $kFPAttributeBit | $kFPCreateDateBit |
                            $kFPModDateBit | $kFPBackupDateBit |
                            $kFPFinderInfoBit | $kFPUnixPrivsBit;
                    not ~$mask & $_[0];
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attributes          => { type => SCALAR, optional => 1 },
        CreateDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ModDate             => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        BackupDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FinderInfo          => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, 0, %options);
    return $kFPParamErr if not defined $ParamsBlock;

    my $msg = pack q{CxS>L>S>a*x![s]a*}, $kFPSetFileDirParms,
            @options{qw[VolumeID DirectoryID Bitmap]},
            PackagePath(@options{qw[PathType Pathname]}),
            $ParamsBlock;
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetFileParms { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper({@options}) });

    my %options = validate(@options, {
        VolumeID            => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        DirectoryID         => {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Bitmap              => {
            type            => SCALAR,
            default         => 0,
            callbacks       => {
                'valid bitmap' => sub {
                    my $mask = $kFPAttributeBit | $kFPCreateDateBit |
                            $kFPModDateBit | $kFPBackupDateBit |
                            $kFPFinderInfoBit | $kFPLaunchLimitBit |
                            $kFPUnixPrivsBit;
                    not ~$mask & $_[0];
                },
            },
        },
        PathType            => {
            type            => SCALAR,
            callbacks       => {
                'valid path type' => sub {
                    $_[0] == $kFPShortName || $_[0] == $kFPLongName ||
                    $_[0] == $kFPUTF8Name
                }
            },
        },
        Pathname            => { type => SCALAR },
        Attributes          => { type => SCALAR, optional => 1 },
        CreateDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ModDate             => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        BackupDate          => {
            type            => SCALAR,
            callbacks       => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        FinderInfo          => { type => SCALAR, optional => 1 },
        UnixUID             => { type => SCALAR, optional => 1 },
        UnixGID             => { type => SCALAR, optional => 1 },
        UnixPerms           => { type => SCALAR, optional => 1 },
        UnixAccessRights    => { type => SCALAR, optional => 1 },
    } );

    my $ParamsBlock = PackSetParams($options{Bitmap}, 0, %options);
    if (not defined $ParamsBlock) {
        return $kFPParamErr;
    }

    my $msg = pack q{CxS>L>S>a*x![s]a*}, $kFPSetFileParms,
            @options{qw[VolumeID DirectoryID Bitmap]},
            PackagePath(@options{qw[PathType Pathname]}),
            $ParamsBlock;
    return $self->SendAFPMessage($msg, undef, 1);
} # }}}1

sub FPSetForkParms { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($OForkRefNum, $Bitmap, $ForkLen) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub {
                    not ~0x4E00 & $_[0]
                }
            }
        },
        {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    my $packed = undef;
    if (($Bitmap & $kFPDataForkLenBit) or
        ($Bitmap & $kFPRsrcForkLenBit)) {
        $packed = pack q{L>}, $ForkLen;
    }
    elsif (($Bitmap & $kFPExtDataForkLenBit) or
             ($Bitmap & $kFPExtRsrcForkLenBit)) {
        $packed = pack q{Q>}, $ForkLen;
    }

    return $self->SendAFPMessage(pack(q{CxS>S>a*}, $kFPSetForkParms,
            $OForkRefNum, $Bitmap, $packed), undef, 1);
} # }}}1

sub FPSetVolParms { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $Bitmap, $BackupDate) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type        => SCALAR,
            callbacks   => {
                'valid bitmap' => sub {
                    not ~0x0010 & $_[0]
                }
            }
        },
        {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );
    return $self->SendAFPMessage(pack(q{CxS>S>L>}, $kFPSetVolParms, $VolumeID,
            $Bitmap, $BackupDate), undef, 1);
} # }}}1

sub FPSyncDir { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($VolumeID, $DirectoryID) = validate_pos(@options,
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        {
            type      => SCALAR,
            callbacks => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>L>}, $kFPSyncDir, $VolumeID,
            $DirectoryID), undef, 1);
} # }}}1

sub FPSyncFork { # {{{1
    my($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($OForkRefNum) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
    );

    return $self->SendAFPMessage(pack(q{CxS>}, $kFPSyncFork, $OForkRefNum),
            undef, 1);
} # }}}1

sub _write_common { # {{{1
    my($self, $lf_mask, $lw_mask, $cmd, $wa, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 4)[3], Dumper({@options}) });

    my %options = validate(@options, {
        Flag        => {
            type        => SCALAR,
            default     => 0,
            callbacks   => {
                'valid flag bits' => sub { not ~0x80 & $_[0] },
            },
        },
        OForkRefNum => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        Offset      => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
        },
        ForkData    => { type => SCALARREF, optional => 1 },
        ReqCount    => {
            type        => SCALAR,
            callbacks   => {
                'value check' => sub {
                    looks_like_number($_[0]);
                },
            },
            optional    => 1,
        },
        FromFH      => { type => HANDLE, optional => 1 },
    } );
    $options{ReqCount} ||= length ${$options{ForkData}};

    my $msg = pack sprintf(q{CCS>%s%s}, $lf_mask, $lf_mask), $cmd,
            @options{qw[Flag OForkRefNum Offset ReqCount]};

    my $resp;
    my $rc = $self->SendAFPWrite($msg, @options{qw[ForkData ReqCount]},
            \$resp, $options{FromFH});
    if ($rc == $kFPNoErr && $wa) {
        return($rc, unpack $lw_mask, $resp);
    }
    return($rc);
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPWrite { # {{{1
    return(_write_common($_[0], q{l>}, q{L>}, $kFPWrite, wantarray, @_[1 .. $#_]));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub FPWriteExt { # {{{1
    return(_write_common($_[0], q{q>}, q{Q>}, $kFPWriteExt, wantarray, @_[1 .. $#_]));
} # }}}1

sub FPZzzzz { # {{{1
    my ($self, @options) = @_;
    $self->{logger}->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([@options]) });

    my($Flags) = validate_pos(@options,
        {
            type        => SCALAR,
            callbacks   => {
                'valid flags' => sub { not ~0x3 & $_[0] }
            },
            optional    => 1,
            default     => 0
        },
    );

    return $self->SendAFPMessage(pack q{CxL>}, $kFPZzzzz, $Flags);
} # }}}1

1;
# vim: ts=4 fdm=marker
