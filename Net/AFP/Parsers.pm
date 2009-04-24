package Net::AFP::Parsers;

use Net::AFP::DirParms;
use Net::AFP::FileParms;
use Net::AFP::VolParms;
use Net::AFP::SrvParms;
use Encode;
use Socket;
use strict;
use warnings;

my $has_Socket6 = 1;
eval { require Socket6; };
if ($@) {
	print "Sorry, Socket6 not available\n" if defined $::__AFP_DEBUG;
	$has_Socket6 = 0;
}

# This is zero time for AFP - 1 Jan 2000 00:00 GMT.
our $globalTimeOffset = 946684800;

sub long_convert {
	my($number) = @_;

	if ($number < 0) {
		$number = ~(-$number - 1) & 0xFFFFFFFF;
	}
	return $number;
}

sub long_unconvert {
	my($number) = @_;

	if ($number & 0x80000000) {
		$number = -((~$number & 0xFFFFFFFF) + 1);
	}
	return $number;
}

sub ll_convert {
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
}

sub ll_unconvert {
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
}

# Parsers for assorted reply types will be placed here. This isn't really
# intended for public consumption - these are only for use in the
# Net::AFP::Connection package and its inheritors. Not that anyone else would
# really know what to do with them anyway.

# FPGetVolParms and FPOpenVol will both need this to parse volume
# parameter info from the server.
sub _ParseVolParms {
	my ($data) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

	my $offset = 2;
	my $Bitmap = unpack('n', $data);
	my $resp = {};

	if ($Bitmap & Net::AFP::VolParms::kFPVolAttributeBit) {
		$$resp{'VolAttribute'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolSignatureBit) {
		$$resp{'Signature'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolCreateDateBit) {
		$$resp{'CreateDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolModDateBit) {
		$$resp{'ModDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolBackupDateBit) {
		$$resp{'BackupDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolIDBit) {
		$$resp{'ID'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolBytesFreeBit) {
		$$resp{'BytesFree'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolBytesTotalBit) {
		$$resp{'BytesTotal'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolNameBit) {
		my $name_off = unpack('x' . $offset . 'n', $data);
		$offset += 2;

		$$resp{'Name'} = decode('MacRoman', unpack('x' . ($name_off + 2) . 'C/a', $data));
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolExtBytesFreeBit) {
		$$resp{'ExtBytesFree'} =
				ll_unconvert(unpack('x[' . $offset . ']NN', $data));
		$offset += 8;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolExtBytesTotalBit) {
		$$resp{'ExtBytesTotal'} = ll_unconvert(unpack('x[' . $offset . ']NN', $data));
		$offset += 8;
	}

	if ($Bitmap & Net::AFP::VolParms::kFPVolBlockSizeBit) {
		$$resp{'BlockSize'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}

	return $resp;
}

# The inheriting classes will need this to parse the response to the
# FPGetSrvrInfo call.
sub _ParseSrvrInfo {
	my ($data) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

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
	#if ($flags & Net::AFP::SrvParms::kSrvrSig) {
	#	$$resp{'ServerSignature'} = substr($data, $sig_off, 16);
	#}

	if ($flags & Net::AFP::SrvParms::kSupportsUTF8SrvrName) {
		$$resp{'UTF8ServerName'} =
				decode_utf8(unpack('x' . $utf8name_off . 'n/a', $data));
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
			print 'unknown address type ', $entryType, ", skipping\n";
			next;
		}
		push(@{$$resp{'NetworkAddresses'}}, $addrEnt);
	}

	if ($flags & Net::AFP::SrvParms::kSupportsDirServices) {
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
}

sub _ParseFileDirParms {
	my ($data) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

	my ($FileBitmap, $DirectoryBitmap, $IsFileDir, $ReqParams) =
			unpack('nnCxa*', $data);

	if ($IsFileDir & 0x80) { # This is a directory
		return _ParseDirParms($DirectoryBitmap, $ReqParams);
	} else { # This is a file
		return _ParseFileParms($FileBitmap, $ReqParams);
	}
}

sub _ParseFileParms {
	my ($Bitmap, $data) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $resp = {};
	my $offset = 0;

	if ($Bitmap & Net::AFP::FileParms::kFPAttributeBit) {
		$$resp{'Attributes'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPParentDirIDBit) {
		$$resp{'ParentDirID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPCreateDateBit) {
		$$resp{'CreateDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPModDateBit) {
		$$resp{'ModDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPBackupDateBit) {
		$$resp{'BackupDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPFinderInfoBit) {
		$$resp{'FinderInfo'} = unpack('x' . $offset . 'a32', $data);
		$offset += 32;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPLongNameBit) {
		my $position = unpack('x' . $offset . 'n', $data);
		$$resp{'LongName'} = decode('MacRoman', unpack('x' . $position . 'C/a', $data));
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPShortNameBit) {
		my $position = unpack('x' . $offset . 'n', $data);
		$$resp{'ShortName'} = unpack('x' . $position . 'C/a', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPNodeIDBit) {
		$$resp{'NodeID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPDataForkLenBit) {
		$$resp{'DataForkLen'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPRsrcForkLenBit) {
		$$resp{'RsrcForkLen'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPExtDataForkLenBit) {
		$$resp{'ExtDataForkLen'} =
				ll_unconvert(unpack('x[' . $offset . ']NN', $data));
		$offset += 8;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPLaunchLimitBit) {
		$$resp{'LaunchLimit'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPUTF8NameBit) {
		my $position = unpack('x[' . $offset . ']n', $data);
		@$resp{'UTF8Hint', 'UTF8Name'} =
				unpack('x' . $position . 'Nn/a', $data);
		$$resp{'UTF8Name'} = decode_utf8($$resp{'UTF8Name'});
		$offset += 6;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPExtRsrcForkLenBit) {
		$$resp{'ExtRsrcForkLen'} =
				ll_unconvert(unpack('x[' . $offset . ']NN', $data));
		$offset += 8;
	}
	if ($Bitmap & Net::AFP::FileParms::kFPUnixPrivsBit) {
		@$resp{'UnixUID', 'UnixGID', 'UnixPerms', 'UnixAccessRights'} =
			unpack('x' . $offset . 'NNNN', $data);
		$offset += 16;
	}
	$$resp{'FileIsDir'} = 0;
	return $resp;
}

sub _ParseDirParms {
	my ($Bitmap, $data) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $resp = {};
	my $offset = 0;

	if ($Bitmap & Net::AFP::DirParms::kFPAttributeBit) {
		$$resp{'Attributes'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPParentDirIDBit) {
		$$resp{'ParentDirID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPCreateDateBit) {
		$$resp{'CreateDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPModDateBit) {
		$$resp{'ModDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPBackupDateBit) {
		$$resp{'BackupDate'} =
				long_unconvert(unpack('x' . $offset . 'N', $data)) +
				$globalTimeOffset;
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPFinderInfoBit) {
		$$resp{'FinderInfo'} = unpack('x' . $offset . 'a32', $data);
		$offset += 32;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPLongNameBit) {
		my $position = unpack('x' . $offset . 'n', $data);
		$$resp{'LongName'} = decode('MacRoman', unpack('x' . $position . 'C/a', $data));
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPShortNameBit) {
		my $position = unpack('x' . $offset . 'n', $data);
		$$resp{'ShortName'} = unpack('x' . $position . 'C/a', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPNodeIDBit) {
		$$resp{'NodeID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPOffspringCountBit) {
		$$resp{'OffspringCount'} = unpack('x' . $offset . 'n', $data);
		$offset += 2;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPOwnerIDBit) {
		$$resp{'OwnerID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPGroupIDBit) {
		$$resp{'GroupID'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPAccessRightsBit) {
		$$resp{'AccessRights'} = unpack('x' . $offset . 'N', $data);
		$offset += 4;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPUTF8NameBit) {
		my $position = unpack('x' . $offset . 'n', $data);
		@$resp{'UTF8Hint', 'UTF8Name'} =
				unpack('x' . $position . 'Nn/a', $data);
		$$resp{'UTF8Name'} = decode_utf8($$resp{'UTF8Name'});
		$offset += 6;
	}
	if ($Bitmap & Net::AFP::DirParms::kFPUnixPrivsBit) {
		@$resp{'UnixUID', 'UnixGID', 'UnixPerms', 'UnixAccessRights'} =
			unpack('x' . $offset . 'NNNN', $data);
		$offset += 16;
	}
	$$resp{'FileIsDir'} = 1;
	return $resp;
}

1;
# vim: ts=4
