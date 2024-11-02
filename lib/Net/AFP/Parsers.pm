package Net::AFP::Parsers;

use strict;
use warnings;
use diagnostics;
use integer;

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

use Net::AFP::DirParms qw(:DEFAULT !:common);
use Net::AFP::FileParms;
use Net::AFP::VolParms;
use Net::AFP::SrvParms;
use Net::AFP::Versions;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Socket qw(AF_INET AF_INET6 inet_ntop AF_APPLETALK);
use Log::Log4perl;
use Data::Dumper;
use POSIX;

my $has_UUID = 0;
eval { require UUID; 1; } and do { $has_UUID = 1; };

use Exporter qw(import);

our @EXPORT = qw(globalTimeOffset ParseVolParms
                 ParseSrvrInfo ParseFileDirParms ParseFileParms
                 ParseDirParms PackSetParams);

# This is zero time for AFP - 1 Jan 2000 00:00 GMT.
sub globalTimeOffset {
    ##no critic qw(RequireInitializationForLocalVars)
    local %ENV;
    ##no critic qw(RequireLocalizedPunctuationVars)
    $ENV{TZ} = q{GMT};
    return mktime(0, 0, 0, 1, 0, 100);
}

# Parsers for assorted reply types will be placed here. This isn't really
# intended for public consumption - these are only for use in the
# Net::AFP package and its inheritors. Not that anyone else would
# really know what to do with them anyway.

my @VolParmFlags = (
    {
        bitval      => $kFPVolAttributeBit,
        fields      => ['Attribute'],
        mask        => q{S>},
        len         => 2,
    },
    {
        bitval      => $kFPVolSignatureBit,
        fields      => ['Signature'],
        mask        => q{S>},
        len         => 2,
    },
    {
        bitval      => $kFPVolCreateDateBit,
        fields      => ['CreateDate'],
        mask        => q{l>},
        len         => 4,
        parse_fixup => sub { $_[1] += globalTimeOffset; },
    },
    {
        bitval      => $kFPVolModDateBit,
        fields      => ['ModDate'],
        mask        => q{l>},
        len         => 4,
        parse_fixup => sub { $_[1] += globalTimeOffset; },
    },
    {
        bitval      => $kFPVolBackupDateBit,
        fields      => ['BackupDate'],
        mask        => q{l>},
        len         => 4,
        parse_fixup => sub { $_[1] += globalTimeOffset; },
    },
    {
        bitval      => $kFPVolIDBit,
        fields      => ['ID'],
        mask        => q{S>},
        len         => 2,
    },
    {
        bitval      => $kFPVolBytesFreeBit,
        fields      => ['BytesFree'],
        mask        => q{L>},
        len         => 4,
    },
    {
        bitval      => $kFPVolBytesTotalBit,
        fields      => ['BytesTotal'],
        mask        => q{L>},
        len         => 4,
    },
    {
        bitval      => $kFPVolNameBit,
        fields      => ['Name'],
        stroff      => q{S>},
        len         => 2,
        mask        => q{C/a},
        parse_fixup => sub {
            # if we're using AFP 3.0 or later, this is UTF8.
            if (Net::AFP::Versions::CompareByVersionNum($_[0], 3, 0,
                    $kFPVerAtLeast)) {
                $_[1] = compose(decode_utf8($_[1]));
            }
            else {
                $_[1] = decode(q{MacRoman}, $_[1]);
            }
        },
    },
    {
        bitval      => $kFPVolExtBytesFreeBit,
        fields      => ['ExtBytesFree'],
        mask        => q{Q>},
        len         => 8,
    },
    {
        bitval      => $kFPVolExtBytesTotalBit,
        fields      => ['ExtBytesTotal'],
        mask        => q{Q>},
        len         => 8,
    },
    {
        bitval      => $kFPVolBlockSizeBit,
        fields      => ['BlockSize'],
        mask        => q{L>},
        len         => 4,
    },

);

# FPGetVolParms and FPOpenVol will both need this to parse volume
# parameter info from the server.
sub ParseVolParms { # {{{1
    my ($data, $obj) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([unpack(q{H*}, $data), $obj]) });

    (my $Bitmap, $data) = unpack q{S>a*}, $data;
    my $offset = 0;
    my $resp   = {};

    my(@values, $pos);
    # rather than having the function spell each one out, let's structure
    # the flag handlers and use a loop.
    foreach my $item (@VolParmFlags) {
        if ($Bitmap & ${$item}{bitval}) {
            if (exists ${$item}{stroff}) { # it's a string offset
                $pos = unpack sprintf(q{x[%d]%s}, $offset, ${$item}{stroff}), $data;
                $offset += exists ${$item}{len} ? ${$item}{len} : 2;
                @values = unpack sprintf(q{x[%d]%s}, $pos, ${$item}{mask}), $data;
            }
            else {
                @values = unpack sprintf(q{x[%d]%s}, $offset, ${$item}{mask}), $data;
                $offset += ${$item}{len};
            }
            if (exists ${$item}{parse_fixup}) {
                &{${$item}{parse_fixup}}($obj, @values);
            }
            @{$resp}{@{${$item}{fields}}} = @values;
        }
    }

    return $resp;
} # }}}1

my @AddrFields = (
    { # packed IPv4 address
        type        => 1,
        parse_field => sub {
            {
                family  => AF_INET,
                address => inet_ntop(AF_INET, $_[0]),
            };
        },
    },
    { # packed IPv4 address + port
        type        => 2,
        parse_field => sub {
            {
                family  => AF_INET,
                address => inet_ntop(AF_INET, unpack q{a[4]x[s]}, $_[0]),
                port    => unpack(q{x[4]S>}, $_[0]),
            };
        },
    },
    { # packed DDP (appletalk) address
        type        => 3,
        parse_field => sub {
            {
                family  => AF_APPLETALK,
                address => sprintf(q{%u.%u}, unpack q{S>Cx}, $_[0]),
                port    => unpack q{x[3]C}, $_[0],
            };
        },
    },
    { # just a DNS name
        type        => 4,
        parse_field => sub { { hostname => $_[0], } },
    },
    { # IPv4 via SSH tunnel
        type        => 5,
        parse_field => sub { { hostname => $_[0], ssh_tunnel => 1, } },
    },
    { # packed IPv6 address
        type        => 6,
        parse_field => sub {
            {
                family  => AF_INET6,
                address => inet_ntop(AF_INET6, $_[0]),
            };
        },
    },
    { # packed IPv6 address + port
        type        => 7,
        parse_field => sub {
            {
                family  => AF_INET6,
                address => inet_ntop(AF_INET6, unpack q{a[16]x[s]}, $_[0]),
                port    => unpack(q{x[16]S>}, $_[0]),
            };
        },
    },
);

my %AddrFieldsByType = map { ${$_}{type}, $_ } @AddrFields;

# The inheriting classes will need this to parse the response to the
# FPGetSrvrInfo call.
sub ParseSrvrInfo { # {{{1
    my ($data) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 3)[3], Dumper([unpack q{H*}, $data]) });

    my $resp = {};

    my $machtype_off = unpack q{S>}, $data;
    (my $afpvers_off, my $uams_off, my $icon_off,
      @{$resp}{qw[Flags ServerName]}, my $extra) =
            unpack q{x[s]S>S>S>S>C/a*x![s]a*}, substr $data, 0, $machtype_off;

    @{$resp}{qw[MachineType AFPVersions UAMs]} =
      (unpack(sprintf(q{x[%d]C/a}, $machtype_off), $data),
      [unpack sprintf(q{x[%d]C/(C/a)}, $afpvers_off), $data],
      [unpack sprintf(q{x[%d]C/(C/a)}, $uams_off), $data],);

    # The server icon is deprecated as of AFP 3.0.
    if ($icon_off) {
        # Convert the binary icon image into a transparent XPM. This makes it
        # supremely usable for anything that uses X, and easily converted into
        # other formats.
        my $icon_text = <<'_EOT_';
/* XPM */
static char *volicon_xpm[] = {
/* width height ncolors chars_per_pixel */
"32 32 3 1",
/* colors */
"  c None",
"_ c #ffffff",
"X c #000000",
_EOT_
        my @data = map { [ split m{}sm ] }
                unpack sprintf(q{x[%d](B[32])[32]}, $icon_off), $data;
        my @mask = map { [ split m{}sm ] }
                unpack sprintf(q{x[%d](B[32])[32]}, $icon_off + 128), $data;
        my @xpm_rows = ();

        for my $i (0 .. 31) {
            my $line;
            $line = q{"};
            for my $j (0 .. 31) {
                $line .= ($mask[$i][$j] ? ($data[$i][$j] ? q{X} : q{_}) : q{ });
            }
            $line .= q{"};
            push @xpm_rows, $line;
        }
        $icon_text .= join(",\n", @xpm_rows) . "};\n";
        ${$resp}{VolumeIcon} = $icon_text;
    }

    if (${$resp}{Flags} & $kSrvrSig) {
        my $sig_off = unpack q{S>}, $extra;
        ${$resp}{ServerSignature} = substr $data, $sig_off, 16;
    }

    if (${$resp}{Flags} & $kSupportsTCP) {
        my $addrs_off = unpack q{x[s]S>}, $extra;
        if ($addrs_off) {
            ${$resp}{NetworkAddresses} = [ map {
                my($entryType, $packed) = unpack q{xCa*}, $_;

                if (not exists $AddrFieldsByType{$entryType}) { # unknown value?
                    $logger->info('unknown address type ', $entryType, ', skipping');
                    next;
                }

                &{${$AddrFieldsByType{$entryType}}{parse_field}}($packed);
            } unpack sprintf(q{x[%d]C/(CX/a)}, $addrs_off), $data ];
        }
    }

    if (${$resp}{Flags} & $kSupportsDirServices) {
        my $dirserv_off = unpack q{x[ss]S>}, $extra;
        ${$resp}{DirectoryNames} =
          [unpack sprintf(q{x[%d]C/(C/a)}, $dirserv_off), $data];
    }

    if (${$resp}{Flags} & $kSupportsUTF8SrvrName) {
        my $utf8name_off = unpack q{x[sss]S>}, $extra;
        ${$resp}{UTF8ServerName} =
          compose(decode_utf8(unpack sprintf(q{x[%d]S>/a}, $utf8name_off),
          $data));
    }

    return $resp;
} # }}}1

sub ParseFileDirParms { # {{{1
    my ($data) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 3)[3], Dumper([unpack q{H*}, $data]) });

    my ($FileBitmap, $DirectoryBitmap, $IsFileDir, $ReqParams) =
            unpack q{S>S>Cxa*}, $data;

    if ($IsFileDir & 0x80) { # This is a directory
        return ParseDirParms($DirectoryBitmap, $ReqParams);
    }
    else { # This is a file
        return ParseFileParms($FileBitmap, $ReqParams);
    }
} # }}}1

my @FileDirParmFlags = (
    {
        bitval      => $kFPAttributeBit,
        fields      => ['Attributes'],
        mask        => q{S>},
        len         => 2,
        file        => 1,
        dir         => 1,
    },
    {
        bitval      => $kFPParentDirIDBit,
        fields      => ['ParentDirID'],
        mask        => q{L>},
        len         => 4,
        file        => 1,
        dir         => 1,
    },
    {
        bitval      => $kFPCreateDateBit,
        fields      => ['CreateDate'],
        mask        => q{l>},
        len         => 4,
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[0] += globalTimeOffset; },
        pack_fixup  => sub { $_[0] -= globalTimeOffset; },
    },
    {
        bitval      => $kFPModDateBit,
        fields      => ['ModDate'],
        mask        => q{l>},
        len         => 4,
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[0] += globalTimeOffset; },
        pack_fixup  => sub { $_[0] -= globalTimeOffset; },
    },
    {
        bitval      => $kFPBackupDateBit,
        fields      => ['BackupDate'],
        mask        => q{l>},
        len         => 4,
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[0] += globalTimeOffset; },
        pack_fixup  => sub { $_[0] -= globalTimeOffset; },
    },
    {
        bitval      => $kFPFinderInfoBit,
        fields      => ['FinderInfo'],
        mask        => q{a[32]},
        len         => 32,
        file        => 1,
        dir         => 1,
    },
    {
        bitval      => $kFPLongNameBit,
        fields      => ['LongName'],
        stroff      => q{S>},
        len         => 2,
        mask        => q{C/a},
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[0] = decode(q{MacRoman}, $_[0]); },
        pack_fixup  => sub { $_[0] = encode(q{MacRoman}, $_[0]); },
    },
    {
        bitval      => $kFPShortNameBit,
        fields      => ['ShortName'],
        stroff      => q{S>},
        len         => 2,
        mask        => q{C/a},
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[0] = decode(q{MacRoman}, $_[0]); },
        pack_fixup  => sub { $_[0] = encode(q{MacRoman}, $_[0]); },
    },
    {
        bitval      => $kFPNodeIDBit,
        fields      => ['NodeID'],
        mask        => q{L>},
        len         => 4,
        file        => 1,
        dir         => 1,
    },
    {
        bitval      => $kFPDataForkLenBit,
        fields      => ['DataForkLen'],
        mask        => q{L>},
        len         => 4,
        file        => 1,
        dir         => 0,
    },
    {
        bitval      => $kFPOffspringCountBit,
        fields      => ['OffspringCount'],
        mask        => q{S>},
        len         => 2,
        file        => 0,
        dir         => 1,
    },
    {
        bitval      => $kFPRsrcForkLenBit,
        fields      => ['RsrcForkLen'],
        mask        => q{L>},
        len         => 4,
        file        => 1,
        dir         => 0,
    },
    {
        bitval      => $kFPOwnerIDBit,
        fields      => ['OwnerID'],
        mask        => q{L>},
        len         => 4,
        file        => 0,
        dir         => 1,
    },
    {
        bitval      => $kFPExtDataForkLenBit,
        fields      => ['ExtDataForkLen'],
        mask        => q{Q>},
        len         => 8,
        file        => 1,
        dir         => 0,
    },
    {
        bitval      => $kFPGroupIDBit,
        fields      => ['GroupID'],
        mask        => q{L>},
        len         => 4,
        file        => 0,
        dir         => 1,
    },
    {
        bitval      => $kFPLaunchLimitBit,
        fields      => ['LaunchLimit'],
        mask        => q{S>},
        len         => 2,
        file        => 1,
        dir         => 0,
    },
    {
        bitval      => $kFPAccessRightsBit,
        fields      => ['AccessRights'],
        mask        => q{L>},
        len         => 4,
        file        => 0,
        dir         => 1,
    },
    {
        bitval      => $kFPUTF8NameBit,
        fields      => [qw(UTF8Hint UTF8Name)],
        stroff      => q{S>x[l]},
        len         => 6, # has a 4 byte pad after the offset
        mask        => q{L>S>/a},
        pack_mask   => q{S>/a}, # don't include hint when packing
        file        => 1,
        dir         => 1,
        parse_fixup => sub { $_[1] = compose(decode_utf8($_[1])); },
        pack_fixup  => sub { $_[0] = encode_utf8(compose($_[0])); },
    },
    {
        bitval      => $kFPExtRsrcForkLenBit,
        fields      => ['ExtRsrcForkLen'],
        mask        => q{Q>},
        len         => 8,
        file        => 1,
        dir         => 0,
    },
    {
        bitval      => $kFPUnixPrivsBit,
        fields      => [qw(UnixUID UnixGID UnixPerms UnixAccessRights)],
        mask        => q{L>L>L>L>},
        len         => 16,
        file        => 1,
        dir         => 1,
    },
    {
        bitval      => $kFPUUID,
        fields      => ['UUID'],
        mask        => q{a[16]},
        len         => 16,
        file        => 0,
        dir         => 1,
        parse_fixup => sub {
            if ($has_UUID) {
                UUID::unparse($_[0], $_[0]);
            }
        },
        pack_fixup  => sub {
            if ($has_UUID) {
                UUID::parse($_[0], $_[0]);
            }
        },
    },
);

sub _parse_common { # {{{1
    my($Bitmap, $data, $typekey, $is_dir) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 4)[3], Dumper([$Bitmap, unpack q{H*}, $data]) });

    my $resp = {};
    my $offset = 0;

    my(@values, $pos);
    foreach my $item (@FileDirParmFlags) {
        next if ${$item}{$typekey} != 1;
        if ($Bitmap & ${$item}{bitval}) {
            if (exists ${$item}{stroff}) { # it's a string offset
                $pos = unpack sprintf(q{x[%d]%s}, $offset, ${$item}{stroff}), $data;
                $offset += exists ${$item}{len} ? ${$item}{len} : 2;
                @values = unpack sprintf(q{x[%d]%s}, $pos, ${$item}{mask}), $data;
            }
            else {
                @values = unpack sprintf(q{x[%d]%s}, $offset, ${$item}{mask}), $data;
                $offset += ${$item}{len};
            }
            if (exists ${$item}{parse_fixup}) {
                &{${$item}{parse_fixup}}(@values);
            }
            @{$resp}{@{${$item}{fields}}} = @values;
        }
    }

    ${$resp}{FileIsDir} = $is_dir;
    return $resp;
} # }}}1

##no critic qw(RequireArgUnpacking)
sub ParseFileParms { # {{{1
    return(_parse_common(@_[0, 1], q{file}, 0));
} # }}}1

##no critic qw(RequireArgUnpacking)
sub ParseDirParms { # {{{1
    return(_parse_common(@_[0, 1], q{dir}, 1));
} # }}}1

sub PackSetParams { # {{{1
    my ($Bitmap, $is_dir, %options) = @_;

    my $ParamsBlock = q{};

    foreach my $item (@FileDirParmFlags) {
        if ($Bitmap & ${$item}{bitval}) {
            next if $is_dir == 0 and ${$item}{file} == 0;
            next if $is_dir == 1 and ${$item}{dir} == 0;
            foreach my $optnam (@{${$item}{fields}}) {
                return if not exists $options{$optnam};
            }
            my @values = @options{@{${$item}{fields}}};
            if (exists ${$item}{pack_fixup}) {
                &{${$item}{pack_fixup}}(@values);
            }
            $ParamsBlock .= pack exists(${$item}{pack_mask}) ? ${$item}{pack_mask} : ${$item}{mask}, @values;
        }
    }

    return $ParamsBlock;
} # }}}1

1;
# vim: ts=4 fdm=marker
