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

use Exporter qw(import);

our @EXPORT = qw(globalTimeOffset ParseVolParms
                 ParseSrvrInfo ParseFileDirParms ParseFileParms
                 ParseDirParms);

# This is zero time for AFP - 1 Jan 2000 00:00 GMT.
sub globalTimeOffset {
    ##no critic qw(RequireInitializationForLocalVars)
    local %ENV;
    ##no critic qw(RequireLocalizedPunctuationVars)
    $ENV{TZ} = q{GMT};
    my $time = mktime(0, 0, 0, 1, 0, 100);
    return $time;
}

# Parsers for assorted reply types will be placed here. This isn't really
# intended for public consumption - these are only for use in the
# Net::AFP package and its inheritors. Not that anyone else would
# really know what to do with them anyway.

# FPGetVolParms and FPOpenVol will both need this to parse volume
# parameter info from the server.
sub ParseVolParms { # {{{1
    my ($data, $obj) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf q{called %s(%s)},
      (caller 3)[3], Dumper([unpack(q{H*}, $data), $obj]) });

    my $offset = 2;
    my $Bitmap = unpack q{S>}, $data;
    my $resp = {};

    if ($Bitmap & $kFPVolAttributeBit) {
        $resp->{Attribute} = unpack sprintf(q{x[%d]S>}, $offset), $data;
        $offset += 2;
    }

    if ($Bitmap & $kFPVolSignatureBit) {
        $resp->{Signature} = unpack sprintf(q{x[%d]S>}, $offset), $data;
        $offset += 2;
    }

    if ($Bitmap & $kFPVolCreateDateBit) {
        $resp->{CreateDate} = unpack(sprintf(q{x[%d]l>}, $offset), $data) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & $kFPVolModDateBit) {
        $resp->{ModDate} = unpack(sprintf(q{x[%d]l>}, $offset), $data) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & $kFPVolBackupDateBit) {
        $resp->{BackupDate} = unpack(sprintf(q{x[%d]l>}, $offset), $data) +
                globalTimeOffset;
        $offset += 4;
    }

    if ($Bitmap & $kFPVolIDBit) {
        $resp->{ID} = unpack sprintf(q{x[%d]S>}, $offset), $data;
        $offset += 2;
    }

    if ($Bitmap & $kFPVolBytesFreeBit) {
        $resp->{BytesFree} = unpack sprintf(q{x[%d]L>}, $offset), $data;
        $offset += 4;
    }

    if ($Bitmap & $kFPVolBytesTotalBit) {
        $resp->{BytesTotal} = unpack sprintf(q{x[%d]L>}, $offset), $data;
        $offset += 4;
    }

    if ($Bitmap & $kFPVolNameBit) {
        my $name_off = unpack sprintf(q{x[%d]S>}, $offset), $data;
        $offset += 2;

        $resp->{Name} = unpack sprintf(q{x[%d]C/a}, $name_off + 2), $data;
        if (Net::AFP::Versions::CompareByVersionNum($obj, 3, 0,
                $kFPVerAtLeast)) {
            $resp->{Name} = compose(decode_utf8($resp->{Name}));
        }
        else {
            $resp->{Name} = decode(q{MacRoman}, $resp->{Name});
        }
    }

    if ($Bitmap & $kFPVolExtBytesFreeBit) {
        $resp->{ExtBytesFree} = unpack sprintf(q{x[%d]Q>}, $offset), $data;
        $offset += 8;
    }

    if ($Bitmap & $kFPVolExtBytesTotalBit) {
        $resp->{ExtBytesTotal} = unpack sprintf(q{x[%d]Q>}, $offset), $data;
        $offset += 8;
    }

    if ($Bitmap & $kFPVolBlockSizeBit) {
        $resp->{BlockSize} = unpack sprintf(q{x[%d]L>}, $offset), $data;
        $offset += 4;
    }

    return $resp;
} # }}}1

# The inheriting classes will need this to parse the response to the
# FPGetSrvrInfo call.
sub ParseSrvrInfo { # {{{1
    my ($data) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 3)[3], Dumper([unpack q{H*}, $data]) });

    my $resp = {};

    my ($machtype_off, $afpvers_off, $uams_off, $icon_off, $flags, $srvname) =
            unpack q{S>S>S>S>S>C/a*}, $data;

    my($sig_off, $addrs_off, $dirserv_off, $utf8name_off);

    # ERRATA: On some pre-AFP-2.2 (maybe all?) implementations, there would
    # be a bunch of space characters between the end of the ServerName
    # field, and the start of the MachineType field.
    my $extra_off = 11 + length $srvname;
    if ($extra_off % 2) { $extra_off++; }
    my $extra = substr $data, $extra_off, $machtype_off - $extra_off;
    # If the slack space after the basic items is just spaces, ignore it.
    if ($extra ne q{ } x length $extra) {
        if ($machtype_off > (12 + length $srvname)) {
            ($sig_off, $addrs_off) = unpack q{x[10]C/xx![s]S>S>}, $data;
        }
        # Enough room for the AFP 3.0-specific fields.
        if ($machtype_off > (16 + length $srvname)) {
            ($dirserv_off, $utf8name_off) = unpack q{x[10]C/xx![s]x[4]S>S>},
                    $data;
        }
    }

    @{$resp}{qw[ServerName Flags MachineType AFPVersions UAMs]}  =
      ($srvname, $flags, unpack(sprintf(q{x[%d]C/a}, $machtype_off), $data),
      [unpack sprintf(q{x[%d]C/(C/a)}, $afpvers_off), $data],
      [unpack sprintf(q{x[%d]C/(C/a)}, $uams_off), $data]);

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
        $resp->{VolumeIcon} = $icon_text;
    }

    if ($flags & $kSrvrSig) {
        $resp->{ServerSignature} = substr $data, $sig_off, 16;
    }

    if ($flags & $kSupportsUTF8SrvrName) {
        $resp->{UTF8ServerName} =
          compose(decode_utf8(unpack sprintf(q{x[%d]S>/a}, $utf8name_off),
          $data));
    }

    if (($flags & $kSupportsTCP) && $addrs_off) {
        $resp->{NetworkAddresses} = [ map {
            my($entryType, $packed) = unpack q{xCa*}, $_;
            my $addrEnt = {};

            if ($entryType == 1) { # Packed IP address
                $addrEnt->{family}  = AF_INET;
                $addrEnt->{address} = inet_ntop(AF_INET, $packed);
            }
            if ($entryType == 2) { # Packed IP address + port
                my($addr, $port) = unpack q{a[4]S>}, $packed;
                $addrEnt->{family}  = AF_INET;
                $addrEnt->{address} = inet_ntop(AF_INET, $addr);
                $addrEnt->{port}    = $port;
            }
            if ($entryType == 3) { # Packed DDP (AppleTalk) address
                $addrEnt->{family}  = AF_APPLETALK;
                $addrEnt->{address} = sprintf '%u.%u', unpack q{S>Cx}, $packed;
                $addrEnt->{port}    = unpack q{x[3]C}, $packed;
            }
            if ($entryType == 4) { # Just the DNS name
                $addrEnt->{hostname} = $packed;
            }
            if ($entryType == 5) { # IPv4 using SSH tunnel
                # Apple's docs say this is a packed IP and port; the netatalk
                # docs, however, indicate this is a string containing an FQDN
                # hostname. Wouldn't be the first time Apple's docs lied.
                # This type is deprecated.
                #print "SSH tunnel type - not sure what needs to be added to handle this right\n";
                $addrEnt->{hostname}   = $packed;
                $addrEnt->{ssh_tunnel} = 1;
            }
            if ($entryType == 6) { # Packed IPv6 address
                $addrEnt->{family}  = AF_INET6;
                $addrEnt->{address} = inet_ntop(AF_INET6, $packed);
            }
            if ($entryType == 7) { # Packed IPv6 address + port
                my($addr, $port) = unpack q{a[16]S>}, $packed;
                $addrEnt->{family}  = AF_INET6;
                $addrEnt->{address} = inet_ntop(AF_INET6, $addr);
                $addrEnt->{port}    = $port;
            }
            if ($entryType < 1 || $entryType > 7) { # unknown value?
                $logger->info('unknown address type ', $entryType, ', skipping');
                next;
            }
            $addrEnt;
        } unpack sprintf(q{x[%d]C/(CX/a)}, $addrs_off), $data ];
    }

    if ($flags & $kSupportsDirServices) {
        $resp->{DirectoryNames} =
          [unpack sprintf(q{x[%d]C/(C/a)}, $dirserv_off), $data];
    }

    return $resp;
} # }}}1

sub ParseFileDirParms { # {{{1
    my ($data) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
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

sub ParseFileParms { # {{{1
    my ($Bitmap, $data) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 3)[3], Dumper([$Bitmap, unpack q{H*}, $data]) });

    my $resp = {};
    my $offset = 0;

    if ($Bitmap & $kFPAttributeBit) {
        $resp->{Attributes} = unpack qq{x[${offset}]S>}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPParentDirIDBit) {
        $resp->{ParentDirID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPCreateDateBit) {
        $resp->{CreateDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPModDateBit) {
        $resp->{ModDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPBackupDateBit) {
        $resp->{BackupDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPFinderInfoBit) {
        $resp->{FinderInfo} = unpack qq{x[${offset}]a[32]}, $data;
        $offset += 32;
    }
    if ($Bitmap & $kFPLongNameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        $resp->{LongName} =
                decode('MacRoman', unpack qq{x[${position}]C/a}, $data);
        $offset += 2;
    }
    if ($Bitmap & $kFPShortNameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        $resp->{ShortName} = unpack qq{x[${position}]C/a}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPNodeIDBit) {
        $resp->{NodeID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPDataForkLenBit) {
        $resp->{DataForkLen} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPRsrcForkLenBit) {
        $resp->{RsrcForkLen} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPExtDataForkLenBit) {
        $resp->{ExtDataForkLen} =
                unpack qq{x[${offset}]Q>}, $data;
        $offset += 8;
    }
    if ($Bitmap & $kFPLaunchLimitBit) {
        $resp->{LaunchLimit} = unpack qq{x[${offset}]S>}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPUTF8NameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        @{$resp}{qw[UTF8Hint UTF8Name]} =
                unpack qq{x[${position}]L>S>/a}, $data;
        $resp->{UTF8Name} = compose(decode_utf8($resp->{UTF8Name}));
        $offset += 6;
    }
    if ($Bitmap & $kFPExtRsrcForkLenBit) {
        $resp->{ExtRsrcForkLen} =
                unpack qq{x[${offset}]Q>}, $data;
        $offset += 8;
    }
    if ($Bitmap & $kFPUnixPrivsBit) {
        @{$resp}{qw[UnixUID UnixGID UnixPerms UnixAccessRights]} =
            unpack qq{x[${offset}]L>L>L>L>}, $data;
        $offset += 16;
    }
    $resp->{FileIsDir} = 0;
    return $resp;
} # }}}1

sub ParseDirParms { # {{{1
    my ($Bitmap, $data) = @_;
    my $logger = Log::Log4perl->get_logger(__PACKAGE__);
    $logger->debug(sub { sprintf 'called %s(%s)',
      (caller 3)[3], Dumper([$Bitmap, unpack q{H*}, $data]) });

    my $resp = {};
    my $offset = 0;

    if ($Bitmap & $kFPAttributeBit) {
        $resp->{Attributes} = unpack qq{x[${offset}]S>}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPParentDirIDBit) {
        $resp->{ParentDirID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPCreateDateBit) {
        $resp->{CreateDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPModDateBit) {
        $resp->{ModDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPBackupDateBit) {
        $resp->{BackupDate} = unpack(qq{x[${offset}]l>}, $data) +
                globalTimeOffset;
        $offset += 4;
    }
    if ($Bitmap & $kFPFinderInfoBit) {
        $resp->{FinderInfo} = unpack qq{x[${offset}]a[32]}, $data;
        $offset += 32;
    }
    if ($Bitmap & $kFPLongNameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        $resp->{LongName} = decode(q{MacRoman},
                unpack qq{x[${position}]C/a}, $data);
        $offset += 2;
    }
    if ($Bitmap & $kFPShortNameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        $resp->{ShortName} = unpack qq{x[${position}]C/a}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPNodeIDBit) {
        $resp->{NodeID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPOffspringCountBit) {
        $resp->{OffspringCount} = unpack qq{x[${offset}]S>}, $data;
        $offset += 2;
    }
    if ($Bitmap & $kFPOwnerIDBit) {
        $resp->{OwnerID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPGroupIDBit) {
        $resp->{GroupID} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPAccessRightsBit) {
        $resp->{AccessRights} = unpack qq{x[${offset}]L>}, $data;
        $offset += 4;
    }
    if ($Bitmap & $kFPUTF8NameBit) {
        my $position = unpack qq{x[${offset}]S>}, $data;
        @{$resp}{qw[UTF8Hint UTF8Name]} =
                unpack qq{x[${position}]L>S>/a}, $data;
        $resp->{UTF8Name} = compose(decode_utf8($resp->{UTF8Name}));
        $offset += 6;
    }
    if ($Bitmap & $kFPUnixPrivsBit) {
        @{$resp}{qw[UnixUID UnixGID UnixPerms UnixAccessRights]} =
            unpack qq{x[${offset}]L>L>L>L>}, $data;
        $offset += 16;
    }
    $resp->{FileIsDir} = 1;
    return $resp;
} # }}}1

1;
# vim: ts=4 fdm=marker
