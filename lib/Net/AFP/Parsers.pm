package Net::AFP::Parsers;

use strict;
use warnings;

use Net::AFP::DirParms qw(:DEFAULT !:common);
use Net::AFP::FileParms;
use Net::AFP::VolParms;
use Net::AFP::SrvParms;
use Encode;
use Unicode::Normalize qw(compose decompose);
use Socket;
use Log::Log4perl qw(:easy);

use Exporter qw(import);

our @EXPORT = qw(globalTimeOffset long_convert long_unconvert ll_convert ll_unconvert uuid_unpack uuid_pack _ParseVolParms _ParseSrvrInfo _ParseFileDirParms _ParseFileParms _ParseDirParms);

my $has_Socket6 = 1;
eval { require Socket6; } or do {
	DEBUG("Sorry, Socket6 not available");
	$has_Socket6 = 0;
};

# This is zero time for AFP - 1 Jan 2000 00:00 GMT.
sub globalTimeOffset { return 946684800; }

sub long_convert { # {{{1
	my($number) = @_;

	if ($number < 0) {
		$number = ~(-$number - 1) & 0xFFFFFFFF;
	}
	return $number;
} # }}}1

sub long_unconvert { # {{{1
	my($number) = @_;

	if ($number & 0x80000000) {
		$number = -((~$number & 0xFFFFFFFF) + 1);
	}
	return $number;
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

	my ($machtype_off, $afpvers_off, $uams_off, $icon_off, $flags,
			$srvname, $sig_off, $addrs_off, $dirserv_off, $utf8name_off) =
			unpack('nnnnnC/a*x![s]nnnn', $data);

	$$resp{'ServerName'} = $srvname;
	$$resp{'Flags'} = $flags;

	$$resp{'MachineType'} = unpack("x" . $machtype_off . "C/a", $data);
	$$resp{'AFPVersions'} =
			[unpack("x" . $afpvers_off . "C/(C/a)", $data)];
	$$resp{'UAMs'} = [unpack("x" . $uams_off . "C/(C/a)", $data)];

	# The server icon is now deprecated.
	my (@icon_data, @icon_mask);
	if ($icon_off > 0) {
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
		my @data_lines = unpack('x' . $icon_off . '(a4)[32]', $data);
		my @mask_lines = unpack('x' . ($icon_off + 128) . '(a4)[32]', $data);
		my @xpm_rows = ();

		for (my $i = 0; $i < 32; $i++) {
			my $line;
			my @data_row = split '', unpack('B*', $data_lines[$i]);
			my @mask_row = split '', unpack('B*', $mask_lines[$i]);
			$line = '"';
			for (my $j = 0; $j < 32; $j++) {
				$line .= ($mask_row[$j] ? ($data_row[$j] ? 'X' : '_') : ' ');
			}
			$line .= '"';
			push(@xpm_rows, $line);
		}
		$icon_text .= join(",\n", @xpm_rows) . "};\n";
		$$resp{'VolumeIconAndMask'} = $icon_text;
	}

	# The server signature doesn't really do anything...
	#if ($flags & kSrvrSig) {
	#	$$resp{'ServerSignature'} = substr($data, $sig_off, 16);
	#}

	if ($flags & kSupportsUTF8SrvrName) {
		$$resp{'UTF8ServerName'} =
				compose(decode_utf8(unpack('x' . $utf8name_off . 'n/a', $data)));
	}

	$$resp{'NetworkAddresses'} = [];
	my ($addrCount) = unpack('x' . $addrs_off . 'C', $data);
	my $offset = $addrs_off + 1;
	for (my $i = 0; $i < $addrCount; $i++) {
		my $addrEnt = {};
		my ($entryLength, $entryType) = unpack('x' . $offset . 'CC', $data);
		my $entry = substr($data, $offset, $entryLength);
		my ($packed) = unpack('xxa*', $entry);
		$offset += $entryLength;
		if ($entryType == 1) { # Packed IP address
			$$addrEnt{'family'} = AF_INET;
			$$addrEnt{'address'} = inet_ntoa($packed);
		} elsif ($entryType == 2) { # Packed IP address + port
			$$addrEnt{'family'} = AF_INET;
			my($addr, $port) = unpack('a4n', $packed);
			$$addrEnt{'address'} = inet_ntoa($addr);
			$$addrEnt{'port'} = $port;
		} elsif ($entryType == 3) { # Packed DDP (AppleTalk) address
			$$addrEnt{'family'} = 5; # aka AF_APPLETALK
			$$addrEnt{'address'} = sprintf('%u.%u:%u', unpack('nCC', $packed));
		} elsif ($entryType == 4) { # Just the DNS name
			$$addrEnt{'hostname'} = $packed;
		} elsif ($entryType == 5) { # IPv4 using SSH tunnel
			# Apple's docs say this is a packed IP and port; the netatalk
			# docs, however, indicate this is a string containing an FQDN
			# hostname. Wouldn't be the first time Apple's docs lied.
			# This type is deprecated.
			#print "SSH tunnel type - not sure what needs to be added to handle this right\n";
			#my($addr, $port) = unpack('a4n', $packed);
			$$addrEnt{'hostname'} = $packed;
			$$addrEnt{'ssh_tunnel'} = 1;
		} elsif ($entryType == 6) { # Packed IPv6 address
			next unless $has_Socket6 == 1;
			$$addrEnt{'family'} = AF_INET6;
			$$addrEnt{'address'} = Socket6::inet_ntop(AF_INET6, $packed);
		} elsif ($entryType == 7) { # Packed IPv6 address + port
			next unless $has_Socket6 == 1;
			$$addrEnt{'family'} = AF_INET6;
			my($addr, $port) = unpack('a16n', $packed);
			$$addrEnt{'address'} = Socket6::inet_ntop(AF_INET6, $addr);
			$$addrEnt{'port'} = $port;
		} else {
			INFO('unknown address type ', $entryType, ", skipping");
			next;
		}
		push(@{$$resp{'NetworkAddresses'}}, $addrEnt);
	}

	if ($flags & kSupportsDirServices) {
		my ($dirservCount) = unpack('x' . $dirserv_off . 'C', $data);
		$$resp{'DirectoryNames'} = [];
		$offset = $dirserv_off + 1;
		for (my $i = 0; $i < $dirservCount; $i++) {
			my ($dirserv_name) = unpack('x' . $offset . 'C/a', $data);
			$offset += length($dirserv_name) + 1;
			push(@{$$resp{'DirectoryNames'}}, $dirserv_name);
		}
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
	} else { # This is a file
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