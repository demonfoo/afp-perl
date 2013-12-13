package Net::AFP::Parsers;

use strict;
use warnings;
use diagnostics;
use integer;

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

use Net::AFP::DirParms qw(:DEFAULT !:common);
use Net::AFP::FileParms;
use Net::AFP::VolParms;
use Net::AFP::SrvParms;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Socket;
use Log::Log4perl qw(:easy);

use Exporter qw(import);

our @EXPORT = qw(globalTimeOffset long_convert long_unconvert ll_convert
                 ll_unconvert uuid_unpack uuid_pack _ParseVolParms
                 _ParseSrvrInfo _ParseFileDirParms _ParseFileParms
                 _ParseDirParms);

my $has_Socket6 = 0;
eval {
    require Socket6;
    1;
} and do {
    $has_Socket6 = 1;
    #Socket6->import();
};

# This is zero time for AFP - 1 Jan 2000 00:00 GMT.
sub globalTimeOffset { return 946684800; }

sub long_convert { # {{{1
    my($number) = @_;

    return unpack('l', pack('L', $number));
} # }}}1

sub long_unconvert { # {{{1
    my($number) = @_;

    return unpack('L', pack('l', $number));
} # }}}1

sub ll_convert { # {{{1
    my($number) = @_;
    
    my($hi, $lo);
    
    if ($number < 0) {
        $number = (-$number - 1);
        $hi = ~int($number / (2 ** 32)) & 0xFFFFFFFF;
        $lo = ~int($number % (2 ** 32)) & 0xFFFFFFFF;
    } else {
        $hi = int($number / (2 ** 32));
        $lo = int($number % (2 ** 32));
    }

    return($hi, $lo);
} # }}}1

sub ll_unconvert { # {{{1
    my($hi, $lo) = @_;

    my $number;

    if ($hi & 0x80000000) {
        $hi = ~$hi & 0xFFFFFFFF;
        $lo = ~$lo & 0xFFFFFFFF;
        $number = -(($hi * (2 ** 32)) + $lo + 1);
    } else {
        $number = ($hi * (2 ** 32)) + $lo;
    }

    return $number;
} # }}}1

sub uuid_unpack { # {{{1
    my($uuid_bin) = @_;
    my @parts = unpack('H[8]H[4]H[4]H[4]H[12]', $uuid_bin);
    my $uuid = join('-', @parts);
    $uuid =~ tr/A-Z/a-z/;
    return $uuid;
} # }}}1

sub uuid_pack { # {{{1
    my($uuid) = @_;
    $uuid = join('', split(/-/, $uuid));
    my $uuid_bin = pack('H32', $uuid);
    return $uuid_bin;
} # }}}1

# Parsers for assorted reply types will be placed here. This isn't really
# intended for public consumption - these are only for use in the
# Net::AFP package and its inheritors. Not that anyone else would
# really know what to do with them anyway.

# FPGetVolParms and FPOpenVol will both need this to parse volume
# parameter info from the server.
sub _ParseVolParms { # {{{1
    my ($data) = @_;
    DEBUG('called ', (caller(0))[3]);

    my $offset = 2;
    my $Bitmap = unpack('n', $data);
    my $resp = {};

    if ($Bitmap & kFPVolAttributeBit) {
        $$resp{'VolAttribute'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }

    if ($Bitmap & kFPVolSignatureBit) {
        $$resp{'Signature'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }

    if ($Bitmap & kFPVolCreateDateBit) {
        $$resp{'CreateDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & kFPVolModDateBit) {
        $$resp{'ModDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & kFPVolBackupDateBit) {
        $$resp{'BackupDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & kFPVolIDBit) {
        $$resp{'ID'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }

    if ($Bitmap & kFPVolBytesFreeBit) {
        $$resp{'BytesFree'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }

    if ($Bitmap & kFPVolBytesTotalBit) {
        $$resp{'BytesTotal'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }

    if ($Bitmap & kFPVolNameBit) {
        my $name_off = unpack('x' . $offset . 'n', $data);
        $offset += 2;

        $$resp{'Name'} = decode('MacRoman', unpack('x' . ($name_off + 2) . 'C/a', $data));
    }

    if ($Bitmap & kFPVolExtBytesFreeBit) {
        $$resp{'ExtBytesFree'} =
                ll_unconvert(unpack('x[' . $offset . ']NN', $data));
        $offset += 8;
    }

    if ($Bitmap & kFPVolExtBytesTotalBit) {
        $$resp{'ExtBytesTotal'} = ll_unconvert(unpack('x[' . $offset . ']NN', $data));
        $offset += 8;
    }

    if ($Bitmap & kFPVolBlockSizeBit) {
        $$resp{'BlockSize'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }

    return $resp;
} # }}}1

# The inheriting classes will need this to parse the response to the
# FPGetSrvrInfo call.
sub _ParseSrvrInfo { # {{{1
    my ($data) = @_;
    DEBUG('called ', (caller(0))[3]);

    my $resp = {};

    my ($machtype_off, $afpvers_off, $uams_off, $icon_off, $flags, $srvname) =
            unpack('nnnnnC/a*', $data);

    # ERRATA: On some pre-AFP-2.2 (maybe all?) implementations, there would
    # be a bunch of space characters between the end of the ServerName
    # field, and the start of the MachineType field.

    my($sig_off, $addrs_off, $dirserv_off, $utf8name_off);
    # The machine type field comes right after the server name; if the offset
    # is large enough to leave room, it's at least AFP 2.2.
    my $extra_off = 11 + length($srvname);
    if ($extra_off % 2) { $extra_off++; }
    my $extra = substr($data, $extra_off, $machtype_off - $extra_off);
    # If the slack space after the basic items is just spaces, ignore it.
    if ($extra ne q{ } x length($extra)) {
        if ($machtype_off > (12 + length($srvname))) {
            ($sig_off, $addrs_off) = unpack('x[10]C/xx![s]nn', $data);
        }
        # Enough room for the AFP 3.0-specific fields.
        if ($machtype_off > (16 + length($srvname))) {
            ($dirserv_off, $utf8name_off) = unpack('x[10]C/xx![s]x[4]nn', $data);
        }
    }

    $$resp{'ServerName'} = $srvname;
    $$resp{'Flags'} = $flags;

    $$resp{'MachineType'} = unpack('x[' . $machtype_off . ']C/a', $data);
    $$resp{'AFPVersions'} =
            [unpack('x[' . $afpvers_off . ']C/(C/a)', $data)];
    $$resp{'UAMs'} = [unpack('x[' . $uams_off . ']C/(C/a)', $data)];

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
        my @data = map { [ split('', $_) ] }
                unpack('x[' . $icon_off . '](B32)[32]', $data);
        my @mask = map { [ split('', $_) ] }
                unpack('x[' . ($icon_off + 128) . '](B32)[32]', $data);
        my @xpm_rows = ();

        for my $i (0 .. 31) {
            my $line;
            $line = '"';
            for my $j (0 .. 31) {
                $line .= ($mask[$i][$j] ? ($data[$i][$j] ? 'X' : '_') : ' ');
            }
            $line .= '"';
            push(@xpm_rows, $line);
        }
        $icon_text .= join(",\n", @xpm_rows) . "};\n";
        $$resp{'VolumeIcon'} = $icon_text;
    }

    if ($flags & kSrvrSig) {
        $$resp{'ServerSignature'} = substr($data, $sig_off, 16);
    }

    if ($flags & kSupportsUTF8SrvrName) {
        $$resp{'UTF8ServerName'} =
                compose(decode_utf8(unpack('x[' . $utf8name_off . ']n/a', $data)));
    }

    if (($flags & kSupportsTCP) && $addrs_off) {
        $$resp{'NetworkAddresses'} = [];
        my @addrlist = map { unpack('xCa*', $_) }
                unpack('x[' . $addrs_off . ']C/(CX/a)', $data);
        while (@addrlist) {
            my $addrEnt = {};
            my($entryType, $packed) = (shift(@addrlist), shift(@addrlist));
            if ($entryType == 1) { # Packed IP address
                $$addrEnt{'family'} = AF_INET;
                $$addrEnt{'address'} = inet_ntoa($packed);
            }
            elsif ($entryType == 2) { # Packed IP address + port
                $$addrEnt{'family'} = AF_INET;
                my($addr, $port) = unpack('a4n', $packed);
                $$addrEnt{'address'} = inet_ntoa($addr);
                $$addrEnt{'port'} = $port;
            }
            elsif ($entryType == 3) { # Packed DDP (AppleTalk) address
                $$addrEnt{'family'} = AF_APPLETALK;
                $$addrEnt{'address'} = sprintf('%u.%u', unpack('nCx', $packed));
                $$addrEnt{'port'} = sprintf('%u', unpack('x[3]C', $packed));
            }
            elsif ($entryType == 4) { # Just the DNS name
                $$addrEnt{'hostname'} = $packed;
            }
            elsif ($entryType == 5) { # IPv4 using SSH tunnel
                # Apple's docs say this is a packed IP and port; the netatalk
                # docs, however, indicate this is a string containing an FQDN
                # hostname. Wouldn't be the first time Apple's docs lied.
                # This type is deprecated.
                #print "SSH tunnel type - not sure what needs to be added to handle this right\n";
                $$addrEnt{'hostname'} = $packed;
                $$addrEnt{'ssh_tunnel'} = 1;
            }
            elsif ($entryType == 6) { # Packed IPv6 address
                next unless $has_Socket6;
                $$addrEnt{'family'} = &Socket6::AF_INET6();
                $$addrEnt{'address'} = Socket6::inet_ntop(&Socket6::AF_INET6(),
                        $packed);
            }
            elsif ($entryType == 7) { # Packed IPv6 address + port
                next unless $has_Socket6;
                $$addrEnt{'family'} = &Socket6::AF_INET6();
                my($addr, $port) = unpack('a16n', $packed);
                $$addrEnt{'address'} = Socket6::inet_ntop(&Socket6::AF_INET6(),
                        $addr);
                $$addrEnt{'port'} = $port;
            }
            else {
                INFO('unknown address type ', $entryType, ", skipping");
                next;
            }
            push(@{$$resp{'NetworkAddresses'}}, $addrEnt);
        }
    }

    if ($flags & kSupportsDirServices) {
        $$resp{'DirectoryNames'} =
                [unpack('x' . $dirserv_off . 'C/(C/a)', $data)];
    }

    return $resp;
} # }}}1

sub _ParseFileDirParms { # {{{1
    my ($data) = @_;
    DEBUG('called ', (caller(0))[3]);

    my ($FileBitmap, $DirectoryBitmap, $IsFileDir, $ReqParams) =
            unpack('nnCxa*', $data);

    if ($IsFileDir & 0x80) { # This is a directory
        return _ParseDirParms($DirectoryBitmap, $ReqParams);
    }
    else { # This is a file
        return _ParseFileParms($FileBitmap, $ReqParams);
    }
} # }}}1

sub _ParseFileParms { # {{{1
    my ($Bitmap, $data) = @_;
    DEBUG('called ', (caller(0))[3]);
    my $resp = {};
    my $offset = 0;

    if ($Bitmap & kFPAttributeBit) {
        $$resp{'Attributes'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPParentDirIDBit) {
        $$resp{'ParentDirID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPCreateDateBit) {
        $$resp{'CreateDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPModDateBit) {
        $$resp{'ModDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPBackupDateBit) {
        $$resp{'BackupDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPFinderInfoBit) {
        $$resp{'FinderInfo'} = unpack('x' . $offset . 'a32', $data);
        $offset += 32;
    }
    if ($Bitmap & kFPLongNameBit) {
        my $position = unpack('x' . $offset . 'n', $data);
        $$resp{'LongName'} = decode('MacRoman', unpack('x' . $position . 'C/a', $data));
        $offset += 2;
    }
    if ($Bitmap & kFPShortNameBit) {
        my $position = unpack('x' . $offset . 'n', $data);
        $$resp{'ShortName'} = unpack('x' . $position . 'C/a', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPNodeIDBit) {
        $$resp{'NodeID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPDataForkLenBit) {
        $$resp{'DataForkLen'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPRsrcForkLenBit) {
        $$resp{'RsrcForkLen'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPExtDataForkLenBit) {
        $$resp{'ExtDataForkLen'} =
                ll_unconvert(unpack('x[' . $offset . ']NN', $data));
        $offset += 8;
    }
    if ($Bitmap & kFPLaunchLimitBit) {
        $$resp{'LaunchLimit'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPUTF8NameBit) {
        my $position = unpack('x[' . $offset . ']n', $data);
        @$resp{'UTF8Hint', 'UTF8Name'} =
                unpack('x' . $position . 'Nn/a', $data);
        $$resp{'UTF8Name'} = compose(decode_utf8($$resp{'UTF8Name'}));
        $offset += 6;
    }
    if ($Bitmap & kFPExtRsrcForkLenBit) {
        $$resp{'ExtRsrcForkLen'} =
                ll_unconvert(unpack('x[' . $offset . ']NN', $data));
        $offset += 8;
    }
    if ($Bitmap & kFPUnixPrivsBit) {
        @$resp{'UnixUID', 'UnixGID', 'UnixPerms', 'UnixAccessRights'} =
            unpack('x' . $offset . 'NNNN', $data);
        $offset += 16;
    }
    $$resp{'FileIsDir'} = 0;
    return $resp;
} # }}}1

sub _ParseDirParms { # {{{1
    my ($Bitmap, $data) = @_;
    DEBUG('called ', (caller(0))[3]);
    my $resp = {};
    my $offset = 0;

    if ($Bitmap & kFPAttributeBit) {
        $$resp{'Attributes'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPParentDirIDBit) {
        $$resp{'ParentDirID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPCreateDateBit) {
        $$resp{'CreateDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPModDateBit) {
        $$resp{'ModDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPBackupDateBit) {
        $$resp{'BackupDate'} =
                long_unconvert(unpack('x' . $offset . 'N', $data)) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & kFPFinderInfoBit) {
        $$resp{'FinderInfo'} = unpack('x' . $offset . 'a32', $data);
        $offset += 32;
    }
    if ($Bitmap & kFPLongNameBit) {
        my $position = unpack('x' . $offset . 'n', $data);
        $$resp{'LongName'} = decode('MacRoman', unpack('x' . $position . 'C/a', $data));
        $offset += 2;
    }
    if ($Bitmap & kFPShortNameBit) {
        my $position = unpack('x' . $offset . 'n', $data);
        $$resp{'ShortName'} = unpack('x' . $position . 'C/a', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPNodeIDBit) {
        $$resp{'NodeID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPOffspringCountBit) {
        $$resp{'OffspringCount'} = unpack('x' . $offset . 'n', $data);
        $offset += 2;
    }
    if ($Bitmap & kFPOwnerIDBit) {
        $$resp{'OwnerID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPGroupIDBit) {
        $$resp{'GroupID'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPAccessRightsBit) {
        $$resp{'AccessRights'} = unpack('x' . $offset . 'N', $data);
        $offset += 4;
    }
    if ($Bitmap & kFPUTF8NameBit) {
        my $position = unpack('x' . $offset . 'n', $data);
        @$resp{'UTF8Hint', 'UTF8Name'} =
                unpack('x' . $position . 'Nn/a', $data);
        $$resp{'UTF8Name'} = compose(decode_utf8($$resp{'UTF8Name'}));
        $offset += 6;
    }
    if ($Bitmap & kFPUnixPrivsBit) {
        @$resp{'UnixUID', 'UnixGID', 'UnixPerms', 'UnixAccessRights'} =
            unpack('x' . $offset . 'NNNN', $data);
        $offset += 16;
    }
    $$resp{'FileIsDir'} = 1;
    return $resp;
} # }}}1

1;
# vim: ts=4 fdm=marker
