#!/usr/bin/perl

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

# Pull in all the AFP packages that we need, for the connection object
# itself and return code symbols, helper functions for version handling
# and UAMs, etc.
use Net::AFP::TCP;
use Net::AFP::Result;
use Net::AFP::VolParms;
use Net::AFP::VolAttrs;
use Net::AFP::UAMs;
use Net::AFP::ACL;
use Net::AFP::MapParms;
use Net::AFP::Versions;
use Net::AFP::FileParms;
use Net::AFP::DirParms;

use Term::ReadLine;		# for reading input from user

use IO::File;
use Text::ParseWords;	# for "shell" style command parsing
use Getopt::Long;		# for command-line option parsing
use Data::Dumper;		# for debugging; remove later
use POSIX;				# for POSIX time handling
use File::Basename;
use Term::ReadPassword;
use Time::HiRes qw(gettimeofday);

use Socket;
my $has_Socket6 = 1;
eval { require Socket6; };
if ($@) {
	$has_Socket6 = 0;
}

use strict;
use warnings;
use diagnostics;

my $has_Text__Glob = 1;
eval { require Text::Glob; };
if ($@) {
	print "Sorry, Text::Glob not available.\n";
	$has_Text__Glob = 0;
}

my $has_Archive__Tar = 1;
eval { require Archive::Tar; };
if ($@) {
	print "Sorry, Archive::Tar not available.\n";
	$has_Archive__Tar = 0;
}

my %UUID_cache = ();

# Turn on some debugging for the AFP and DSI layers. Can produce a _lot_ of
# output - use with care.
our $__AFP_DEBUG;
our $__DSI_DEBUG;

GetOptions( 'debug-afp' => sub { $__AFP_DEBUG = 1; },
			'debug-dsi' => sub { $__DSI_DEBUG = 1; } );

my($path) = @ARGV;
my $afp_url_pattern = qr|^
                          (afps?):/		    # protocol specific prefix
						  (at)?/            # optionally specify atalk transport
						  (?:               # authentication info block
						      ([^:\@\/;]*)  # capture username
							  (?:;AUTH=([^:\@\/;]+))? # capture uam name
							  (?::([^:\@\/;]*))?      # capture password
							  \@)?          # closure of auth info capture
                          ([^:\/\@;]+)      # capture target host
						  (?::([^:\/\@;]+))? # capture optional port
						  (?:\/(?:          # start path capture
							  ([^:\/\@;]+)  # first path element is vol name
							  (\/.*)?       # rest of path is local subpath
                          )?)?              # closure of path capture
						 $|x;
my @args = ('protocol', 'atalk_transport', 'username', 'UAM', 'password', 'host', 'port', 'volume', 'subpath');
my %values;

unless (@values{@args} = $path =~ $afp_url_pattern) {
	print "Volume path ", $path, " is not valid, sorry.\n";
	exit(1);
}
foreach (keys(%values)) { $values{$_} = urldecode($values{$_}); }

my($host, $volume) = @values{'host', 'volume'};

die("Appletalk transport not available") if defined $values{'atalk_transport'};

my $srvInfo;
my $session = doAFPConnection(@values{'host', 'port', 'username', 'password', 'UAM'}, \$srvInfo);

# If no volume was named, contact the server and find out the volumes
# it knows, and spit those out in a friendly format.
unless (defined $volume) {
	my $srvrParms;
	$session->FPGetSrvrParms(\$srvrParms);
	print <<'_EOT_';

Volume Name                                 | UNIX privs? | Volume pass?
-------------------------------------------------------------------------
_EOT_
	foreach my $volume (@{$$srvrParms{'Volumes'}}) {
		printf("\%-43s |     \%-3s     |     \%s\n", $$volume{'VolName'}, $$volume{'HasUNIXPrivs'} ? 'Yes' : 'No', $$volume{'HasPassword'} ? 'Yes' : 'No');
	}

	$session->FPLogout();
	$session->close();
	exit(0);
}

my $volInfo;
my $rc = $session->FPOpenVol(kFPVolAttributeBit, $volume, undef, \$volInfo);
unless ($rc == kFPNoErr) {
	print "Volume was unknown?\n";
	$session->FPLogout();
	$session->close();
	exit(1);
}

my $volID = $$volInfo{'ID'};
my $DT_ID;
$rc = $session->FPOpenDT($volID, \$DT_ID);
unless ($rc == kFPNoErr) {
	print "Couldn't open Desktop DB\n";
	undef $DT_ID;
#	$session->FPCloseVol($volID);
#	$session->FPLogout();
#	$session->close();
}

my $volAttrs = $$volInfo{'VolAttribute'};

my $pathType	= kFPLongName;
my $pathFlag	= kFPLongNameBit;
my $pathkey		= 'LongName';

if ($volAttrs & kSupportsUTF8Names) {
	# If the remote volume does UTF8 names, then we'll go with that..
	$pathType		= kFPUTF8Name;
	$pathFlag		= kFPUTF8NameBit;
	$pathkey		= 'UTF8Name';
}

my $topDirID = 2;
my $term = new Term::ReadLine 'afpsh';
my $curdirnode = $topDirID;

my $DForkLenFlag	= kFPDataForkLenBit;
my $RForkLenFlag	= kFPRsrcForkLenBit;
my $DForkLenKey		= 'DataForkLen';
my $RForkLenKey		= 'RsrcForkLen';
my $UseExtOps		= 0;
# I *think* large file support entered the picture as of AFP 3.0...
if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
		kFPVerAtLeast)) {
	$DForkLenFlag	= kFPExtDataForkLenBit;
	$RForkLenFlag	= kFPExtRsrcForkLenBit;
	$DForkLenKey	= 'ExtDataForkLen';
	$RForkLenKey	= 'ExtRsrcForkLen';
	$UseExtOps		= 1;
}

if (defined $values{'subpath'}) {
	my ($newDirId, $fileName) = resolve_path($session, $volID,
			$values{'subpath'});
	if (defined $fileName or !defined $newDirId) {
		print "path ", $values{'subpath'}, " is not accessible, defaulting to volume root\n";
	}
	else {
		$curdirnode = $newDirId;
	}
}

my %commands = (
	'ls'	=> sub {
		my @words = @_;
		my $fileBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
				kFPNodeIDBit | $DForkLenFlag | $RForkLenFlag |
				kFPParentDirIDBit | $pathFlag;
		if ($$volInfo{'VolAttribute'} & kSupportsUnixPrivs) {
			$fileBmp |= kFPUnixPrivsBit;
		}
		my $dirBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
				kFPNodeIDBit | kFPOffspringCountBit | kFPOwnerIDBit |
				kFPGroupIDBit | kFPAccessRightsBit | kFPParentDirIDBit |
				$pathFlag;
		if ($$volInfo{'VolAttribute'} & kSupportsUnixPrivs) {
			$dirBmp |= kFPUnixPrivsBit;
		}
		my $printDirNames = 0;
		if (scalar(@words) > 2) {
			$printDirNames = 1;
		}
		if (scalar(@words) < 2) {
			push(@words, '.');
		}
		foreach my $item (@words[1 .. $#words]) {
			my $results;
			my @records;
			my $rc;
			my ($dirId, $fileName) = resolve_path($session, $volID, $item);
			unless (defined $dirId) {
				print "Sorry, couldn't find named entry \"", $item, "\"\n";
				next;
			}
			if (defined $fileName) {
				my $resp = '';
				$rc = $session->FPGetFileDirParms($volID, $dirId, $fileBmp,
					$dirBmp, $pathType, $fileName, \$resp);
				if ($rc == kFPNoErr) {
					push(@records, $resp);
				}
			}
			else {
				my $offset = 1;
				do {
					$results = undef;
					my @arglist = ($volID, $dirId, $fileBmp, $dirBmp,
							1024, $offset, 32767, $pathType, '', \$results);
					$rc = $session->FPEnumerateExt2(@arglist);
					if ($rc == kFPCallNotSupported) {
						$rc = $session->FPEnumerateExt(@arglist);
					}
					if ($rc == kFPCallNotSupported) {
						$rc = $session->FPEnumerate(@arglist);
					}
					if (ref($results) eq 'ARRAY') {
						push(@records, @$results);
						$offset += scalar(@$results);
					}
				} while ($rc == kFPNoErr);
			}
			if ($rc == kFPNoErr || $rc == kFPObjectNotFound) {
				if ($printDirNames == 1 and !defined($fileName)) {
					print $item, ":\n";
				}
				do_listentries(\@records, $volID);
				if ($printDirNames == 1 and !defined($fileName)) {
					print "\n";
				}
			}
		}
		return 1;
	},
	'cat'	=> sub {
		my @words = @_;
		foreach my $fname (@words[1..$#words]) {
			my ($dirId, $fileName) = resolve_path($session, $volID, $fname);
			my $resp = '';
			my $rc = $session->FPOpenFork(0, $volID, $dirId, 0, 0x1,
					$pathType, $fileName, \$resp);
			if ($rc != kFPNoErr) {
				print "open attempt failed with code ", $rc, "\n";
				next;
			}
			my $pos = 0;
			while (1) {
				my $data = '';
				if ($UseExtOps) {
					$rc = $session->FPReadExt($$resp{'OForkRefNum'}, $pos,
							1024, \$data);
				}
				else {
					$rc = $session->FPRead($$resp{'OForkRefNum'}, $pos, 1024,
							undef, undef, \$data);
				}
				print $data;
				if ($rc != kFPNoErr) {
					last;
				}
				$pos += 1024;
			}
			$rc = $session->FPCloseFork($$resp{'OForkRefNum'});
			if ($rc != kFPNoErr) {
				print "close attempt failed with code ", $rc, "\n";
			}
		}
		return 1;
	},
	'cd'	=> sub {
		my @words = @_;
		my $path;
		if (scalar(@words) == 1) {
			$path = '/';
		}
		elsif (scalar(@words) == 2) {
			$path = $words[1];
		}
		else {
			print "Incorrect number of arguments\n";
			return 1;
		}
		my ($newDirId, $fileName) = resolve_path($session, $volID,
				$words[1]);
		if (defined $fileName or !defined $newDirId) {
			print "sorry, couldn't change directory\n";
			return 1;
		}
		$curdirnode = $newDirId;
		return 1;
	},
	'get'	=> sub {
		my @words = @_;
		print "note that the resource fork isn't handled yet!\n";
		if (scalar(@words) < 2 or scalar(@words) > 3) {
			print <<'_EOT_';
Error: Specify the name of the file to retrieve, and optionally the name of
the file to store the local copy to. Quote the name if needed (to account
for spaces or special characters).
_EOT_
			return 1;
		}
		my ($dirId, $fileName) = resolve_path($session, $volID,
				$words[1]);
		unless (defined $dirId) {
			print <<'_EOT_';
Error: Couldn't resolve path; possibly no such file?
_EOT_
			return 1;
		}
		unless (defined $fileName) {
			print <<'_EOT_';
Error: Not a file; you must specify the name of a file to retrieve.
_EOT_
			return 1;
		}
		my $targetFile = (scalar(@words) == 2 ? $fileName : $words[2]);
		my $resp = '';
		my $rc = $session->FPOpenFork(0, $volID, $dirId, 0, 0x1,
				$pathType, $fileName, \$resp);
		if ($rc != kFPNoErr) {
			print "open attempt failed with code ", $rc, "\n";
			return 1;
		}
		
		my $local_fh = new IO::File($targetFile, 'w');
		unless (defined $local_fh) {
			print "Couldn't open local file for writing!\n";
			$session->FPCloseFork($$resp{'OForkRefNum'});
			return 1;;
		}

		my $sresp = '';
		my $bitmap = $DForkLenFlag;
		$rc = $session->FPGetForkParms($$resp{'OForkRefNum'}, $bitmap, \$sresp);
		$| = 1;
		my $pos = 0;
		my(%time, %lasttime, %starttime);
		@time{'sec', 'usec'} = gettimeofday();
		%starttime = %time;
		while (1) {
			my $data = '';
			if ($UseExtOps) {
				$rc = $session->FPReadExt($$resp{'OForkRefNum'}, $pos,
						131072, \$data);
			}
			else {
				$rc = $session->FPRead($$resp{'OForkRefNum'}, $pos, 131072,
						undef, undef, \$data);
			}
			print $local_fh $data;
			my $rate = 0;
			my $delta = (($time{'sec'} - $starttime{'sec'}) + (($time{'usec'} - $starttime{'usec'}) / 1000000.0));
			my $mult = ' ';
			if ($delta > 0) {
				$rate = $pos / $delta;
				if ($rate > 1000) {
					$rate /= 1000.0;
					$mult = 'K';
				}
				if ($rate > 1000) {
					$rate /= 1000.0;
					$mult = 'M';
				}
			}
			my $pcnt = ($pos + length($data)) * 100 / $$sresp{$DForkLenKey};
			printf(' %3d%%  |%-25s|  %-28s  %5.2f %sB/sec' . "\r", $pcnt, '*' x ($pcnt * 25 / 100), substr($fileName, 0, 28), $rate, $mult);
			last if $rc != kFPNoErr;
			$pos += length($data);
			%lasttime = %time;
			@time{'sec', 'usec'} = gettimeofday();
		}
		print "\n";
		close($local_fh);
		$rc = $session->FPCloseFork($$resp{'OForkRefNum'});
		if ($rc != kFPNoErr) {
			print "close attempt failed with code ", $rc, "\n";
		}
		return 1;
	},
	'put'	=> sub {
		my @words = @_;
		if (scalar(@words) < 2 or scalar(@words) > 3) {
			print <<'_EOT_';
Error: Specify the name of the file to send, and optionally the name of
the file to store the remote copy to. Quote the name if needed (to account
for spaces or special characters).
_EOT_
			return 1;
		}

		my $srcFileName = basename($words[1]);
		my $targetFile = (scalar(@words) == 2 ? $srcFileName : $words[2]);
		my ($dirID, $fileName) = resolve_path($session, $volID,
				$targetFile, 0, 1);
		unless (defined $dirID) {
			print <<'_EOT_';
Error: Couldn't resolve path; possibly no such file?
_EOT_
			return 1;
		}
		unless (defined $fileName) {
			$fileName = $srcFileName;
		}
		
		my $srcFile = new IO::File($words[1], 'r');
		unless (defined $srcFile) {
			print "couldn't open source file\n";
			return 1;
		}
		my $rc = $session->FPCreateFile(0x80, $volID, $dirID, $pathType,
				$fileName);
		if ($rc != kFPNoErr) {
			print "Couldn't create file on remote server; server returned code ", $rc, "\n";
			return 1;
		}
		my $resp = '';
		$rc = $session->FPOpenFork(0, $volID, $dirID, 0, 0x2, $pathType,
				$fileName, \$resp);
		if ($rc != kFPNoErr) {
			print "open attempt failed with code ", $rc, "\n";
			return 1;
		}

		my $fileLen = (stat($srcFile))[7];
		$| = 1;
		my $pos = 0;
		my(%time, %lasttime, %starttime);
		@time{'sec', 'usec'} = gettimeofday();
		%starttime = %time;
		while (1) {
			my $data = '';
			my $rcnt = read($srcFile, $data, 131072);
			last if $rcnt == 0;
			my $sresp = '';
			if ($UseExtOps) {
				$rc = $session->FPWriteExt(0x80, $$resp{'OForkRefNum'}, 0,
						length($data), \$data, \$sresp);
			}
			else {
				$rc = $session->FPWrite(0x80, $$resp{'OForkRefNum'}, 0,
						length($data), \$data, \$sresp);
			}
			#if ($hashmarks_enabled == 1) {
#			my $pcnt = ($pos + length($data)) * 100 / $fileLen;
#			printf(' %3d%%  |%-25s|  %-.42s' . "\r", $pcnt, '*' x ($pcnt * 25 / 100), $srcFileName);
			my $rate = 0;
			my $delta = (($time{'sec'} - $starttime{'sec'}) + (($time{'usec'} - $starttime{'usec'}) / 1000000.0));
			my $mult = ' ';
			if ($delta > 0) {
				$rate = $pos / $delta;
				if ($rate > 1000) {
					$rate /= 1000.0;
					$mult = 'K';
				}
				if ($rate > 1000) {
					$rate /= 1000.0;
					$mult = 'M';
				}
			}
			my $pcnt = ($pos + length($data)) * 100 / $fileLen;
			printf(' %3d%%  |%-25s|  %-28s  %5.2f %sB/sec' . "\r", $pcnt, '*' x ($pcnt * 25 / 100), $fileName, $rate, $mult);
			last if $rc != kFPNoErr;
			$pos += $rcnt;
			%lasttime = %time;
			@time{'sec', 'usec'} = gettimeofday();
			#}
			unless ($rc == kFPNoErr) {
				print "Write to file on server failed with return code ", $rc, "\n";
				last;
			}
		}
		#if ($hashmarks_enabled == 1) {
		print "\n";
		#}
		close($srcFile);
		$rc = $session->FPCloseFork($$resp{'OForkRefNum'});
		if ($rc != kFPNoErr) {
			print "close attempt failed with code ", $rc, "\n";
		}
		return 1;
	},
	'mkdir'	=> sub {
		my @words = @_;
		if (scalar(@words) != 2) {
			print <<'_EOT_';
Please specify the name of the directory to create.
_EOT_
			return 1;
		}
		# FIXME: need to resolve the provided path, but path resolver needs
		# to be modified to handle the "final element of split path doesn't
		# exist yet" condition.
		my $newDirID = '';
		my $rc = $session->FPCreateDir($volID, $curdirnode, $pathType,
				$words[1], \$newDirID);
		if ($rc != kFPNoErr) {
			print "sorry, couldn't create requested directory; response was ", $rc, "\n";
		}
		return 1;
	},
	'rm'	=> sub {
		my @words = @_;
		if (scalar(@words) < 2) {
			print <<'_EOT_';
Please specify the name of one or more files or directories to remove.
_EOT_
			return 1;
		}
		# FIXME: need to resolve the provided path, but path resolver needs
		# to be modified to handle the "final element of split path doesn't
		# exist yet" condition.
		my ($dirID, $fileName) = resolve_path($session, $volID, $words[1],
				1, 0);
		unless (defined $dirID) {
			print <<'_EOT_';
Error: Couldn't resolve path; possibly no such file?
_EOT_
			return 1;
		}
		unless (defined $fileName) {
			print <<'_EOT_';
Error: Name not found; possibly does not exist?
_EOT_
			return 1;
		}
		my $rc = $session->FPDelete($volID, $dirID, $pathType,
				$fileName);
		if ($rc != kFPNoErr) {
			print "sorry, couldn't remove item; response was ", $rc, "\n";
		}
		return 1;
	},
	'pwd'	=> sub {
		my @words = @_;
		my $entry = undef;
		my $searchID = $curdirnode;
		my @nameParts;
		while ($searchID != $topDirID) {
			my $dirbits = kFPParentDirIDBit | $pathFlag;
			my $rc = $session->FPGetFileDirParms($volID, $searchID, 0,
					$dirbits, $pathType, '', \$entry);
			push(@nameParts, $$entry{$pathkey});
			$searchID = $$entry{'ParentDirID'};
		}
		print "current directory is /", join('/', reverse(@nameParts)), "\n";
		return 1;
	},
	'exit'	=> sub {
		return undef;
	},
	'get_acl'	=> sub {
		my @words = @_;
		foreach my $fname (@words[1..$#words]) {
			my ($dirId, $fileName) = resolve_path($session, $volID,
					$fname);
			my $resp = undef;
			my $rc = $session->FPGetACL($volID, $dirId,
					kFileSec_UUID | kFileSec_GRPUUID | kFileSec_ACL,
					0, $pathType, $fileName, \$resp);
			if ($rc != kFPNoErr) {
				print "Sorry, file/directory was not found\n";
				return 1;
			}
			print "ACL for \"", $fname, "\":\n";
			print Dumper($resp);
		}
		return 1;
	},
	'get_comment'	=> sub {
		my @words = @_;
		foreach my $fname (@words[1..$#words]) {
			my ($dirId, $fileName) = resolve_path($session, $volID, $fname);
			my $resp = undef;
			next unless defined $DT_ID;
			my $rc = $session->FPGetComment($DT_ID, $dirId, $pathType,
					$fileName, \$resp);
			if ($rc != kFPNoErr) {
				print "Sorry, file/directory was not found\n";
				return;
			}
			print "Comment for \"", $fname, "\":\n", $resp, "\n";
		}
		return 1;
	},
);
$commands{'dir'} = $commands{'ls'};
$commands{'delete'} = $commands{'rm'};
$commands{'quit'} = $commands{'exit'};

while (1) {
	my $line = $term->readline('afpsh$ ');
	if (!defined($line)) {
		print "\n";
		last;
	}
	my @words = shellwords($line);
	next if (!defined($words[0]) || ($words[0] eq ''));
	if (exists $commands{$words[0]}) {
		my $rv = &{$commands{$words[0]}}(@words);
		last unless $rv;
	}
	else {
		print "Sorry, unknown command\n";
	}
}

sub do_listentries {
	my ($results, $volID) = @_;
	@$results = sort { $$a{$pathkey} cmp $$b{$pathkey} } @$results;
	foreach my $ent (@$results) {
		my $fmodtime = $$ent{'ModDate'};
		my $tfmt = '%b %e  %Y';
		if (time() - $fmodtime < 6 * 30 * 24 * 60 * 60) {
			$tfmt = '%b %e %H:%M';
		}
		my $up = $$ent{'UnixPerms'};
		printf('%s%s%s%s%s%s%s%s%s%s %3d %5d %5d %8s %-11s %s' . "\n",
			($$ent{'FileIsDir'} == 1 ? 'd' : '-'),
			($up & 0400 ? 'r' : '-'),
			($up & 0200 ? 'w' : '-'),
			($up & 04000 ? ($up & 0100 ? 's' : 'S') : ($up & 0100 ? 'x' : '-')),
			($up & 0040 ? 'r' : '-'),
			($up & 0020 ? 'w' : '-'),
			($up & 02000 ? ($up & 0010 ? 's' : 'S') : ($up & 0010 ? 'x' : '-')),
			($up & 0004 ? 'r' : '-'),
			($up & 0002 ? 'w' : '-'),
			($up & 01000 ? ($up & 0001 ? 't' : 'T') : ($up & 0001 ? 'x' : '-')),
			($$ent{'FileIsDir'} == 1 ? $$ent{'OffspringCount'} + 2 : 1),
			$$ent{'UnixUID'}, $$ent{'UnixGID'},
			($$ent{'FileIsDir'} == 1 ? 0 : $$ent{$DForkLenKey}),
			strftime($tfmt, localtime($fmodtime)),
			$$ent{$pathkey});
		my $acl_info;
		my $rc = $session->FPGetACL($volID, $$ent{'ParentDirID'},
				kFileSec_ACL, 0, $pathType, $$ent{$pathkey}, \$acl_info);
		if ($rc == kFPNoErr && ($$acl_info{'Bitmap'} & kFileSec_ACL)) {
			for (my $i = 0; $i <= $#{$$acl_info{'acl_ace'}}; $i++) {
				my $entry = ${$$acl_info{'acl_ace'}}[$i];
				my $name;
				my @args = ();
				my $rc = $session->FPMapID(kUserUUIDToUTF8Name,
						$$entry{'ace_applicable'}, \$name);
				my $idtype;
				if ($$name{'Bitmap'} == kFileSec_UUID) {
					$idtype = 'user';
				}
				elsif ($$name{'Bitmap'} == kFileSec_GRPUUID) {
					$idtype = 'group';
				}

				my $acl_kind = $$entry{'ace_flags'} & KAUTH_ACE_KINDMASK;
				my $kind = 'unknown';
				if ($acl_kind == KAUTH_ACE_PERMIT) {
					$kind = 'allow';
				}
				elsif ($acl_kind == KAUTH_ACE_DENY) {
					$kind = 'deny';
				}

				my @actions = ();
				my $rights = $$entry{'ace_rights'};
				if ($rights & KAUTH_VNODE_READ_DATA) {
					push(@actions, $$ent{'FileIsDir'} ? 'list' : 'read');
				}
				if ($rights & KAUTH_VNODE_WRITE_DATA) {
					push(@actions, $$ent{'FileIsDir'} ? 'add_file' : 'write');
				}
				if ($rights & KAUTH_VNODE_EXECUTE) {
					push(@actions, $$ent{'FileIsDir'} ? 'search' : 'execute');
				}
				if ($rights & KAUTH_VNODE_DELETE) {
					push(@actions, 'delete');
				}
				if ($rights & KAUTH_VNODE_APPEND_DATA) {
					push(@actions, $$ent{'FileIsDir'} ? 'add_subdirectory' : 'append');
				}
				if ($rights & KAUTH_VNODE_DELETE_CHILD) {
					push(@actions, 'delete_child');
				}
				if ($rights & KAUTH_VNODE_READ_ATTRIBUTES) {
					push(@actions, 'readattr');
				}
				if ($rights & KAUTH_VNODE_WRITE_ATTRIBUTES) {
					push(@actions, 'writeattr');
				}
				if ($rights & KAUTH_VNODE_READ_EXTATTRIBUTES) {
					push(@actions, 'readextattr');
				}
				if ($rights & KAUTH_VNODE_WRITE_EXTATTRIBUTES) {
					push(@actions, 'writeextattr');
				}
				if ($rights & KAUTH_VNODE_READ_SECURITY) {
					push(@actions, 'readsecurity');
				}
				if ($rights & KAUTH_VNODE_WRITE_SECURITY) {
					push(@actions, 'writesecurity');
				}
				if ($rights & KAUTH_VNODE_CHANGE_OWNER) {
					push(@actions, 'chown');
				}

				printf(" \%d: \%s:\%s \%s \%s\n", $i, $idtype,
						$$name{'UTF8Name'}, $kind, @actions);
			}
		}
	}
}

# $lastIfDir - the last element can be a directory; needed for removing
# directories, like for FPRemove
# $lastNoExist - the last element might not exist, like for FPCreateFile (i.e.,
# for use as part of the "put" command)
sub resolve_path {
	my ($session, $volid, $path, $lastIfDir, $lastNoExist) = @_;

	if (!defined($lastIfDir)) {
		$lastIfDir = 0;
	}
	if (!defined($lastNoExist)) {
		$lastNoExist = 0;
	}

	my $dirBmp = kFPNodeIDBit | kFPParentDirIDBit;
	my $fileBmp = 0;
	my $fileName = undef;

	my @pathElements = split('/', $path);
	my $curNode = $curdirnode;
	if (!defined($pathElements[0]) || ($pathElements[0] eq '')) {
		$curNode = 2;
		shift(@pathElements);
	}
	for (my $i = 0; $i < scalar(@pathElements); $i++) {
		my $elem = $pathElements[$i];
		my $getParentID = 0;
		next if $elem eq '.' or $elem eq '';
		if ($elem eq '..') {
			next if $curNode == 2;
			$elem = '';
			$getParentID = 1;
		}
		my $resp = '';
		my $rc = $session->FPGetFileDirParms($volid, $curNode, $fileBmp,
				$dirBmp, $pathType, $elem, \$resp);
		if (($lastNoExist == 1 and $rc == kFPObjectNotFound) or
				($rc == kFPNoErr and $$resp{'FileIsDir'} != 1)) {
			if ($i == $#pathElements) {
				$fileName = $elem;
				last;
			}
			else {
				return(undef);
			}
		}
		return(undef) if $rc != kFPNoErr;
		$curNode = ($getParentID == 1 ? $$resp{'ParentDirID'} :
				$$resp{'NodeID'});
	}
	return($curNode, $fileName);
}

$session->FPCloseDT($DT_ID) if defined $DT_ID;
$session->FPCloseVol($volID);
$session->FPLogout();
$session->close();
exit(0);

sub doAFPConnection {
	my($host, $port, $user, $password, $uam, $srvinf_r) = @_;
	my $srvInfo;
	my $rc = Net::AFP::TCP->GetStatus($host, $port, \$srvInfo);
	if ($rc != kFPNoErr) {
		print "Could not issue GetStatus on ", $host, "\n";
		exit(1);
	}
	if (ref($srvinf_r) eq 'SCALAR') {
		$$srvinf_r = $srvInfo;
	}

	my $session = new Net::AFP::TCP($host, $port);
	unless (ref($session) ne '' and $session->isa('Net::AFP')) {
		print "Could not connect via AFP to ", $host, "\n";
		exit(1);
	}

	my $commonVersion = Net::AFP::Versions::GetPreferredVersion($$srvInfo{'AFPVersions'});
	unless (defined $commonVersion) {
		print "Couldn't agree on an AFP protocol version with the server\n";
		$session->close();
		exit(1);
	}
#	print "determined commonVersion should be '", $commonVersion, "'\n";

	if (defined $user) {
#		my $term = new Term::ReadLine 'afpsh';
#		my $attribs = $term->Attribs;
#		my $redisp_fn = $$attribs{'redisplay_function'};
#		$$attribs{'redisplay_function'} = $$attribs{'shadow_redisplay'};
#		my $password = $term->readline('Password: ');
#		$$attribs{'redisplay_function'} = $redisp_fn;
		my $uamlist = $$srvInfo{'UAMs'};
		if (defined $uam) {
			$uamlist = [ $uam ];
		}
		my $rc = Net::AFP::UAMs::PasswordAuth($session, $commonVersion,
				$uamlist, $user, sub {
					my $prompt = 'Password: ';
					return $password if defined $password;
					return Term::ReadPassword::read_password($prompt);
				});
		unless ($rc == kFPNoErr) {
			print "Incorrect username/password while trying to authenticate\n";
			$session->close();
			exit(1);
		}
	}
	else {
		my $rc = Net::AFP::UAMs::GuestAuth($session, $commonVersion);
		unless ($rc == kFPNoErr) {
			print "Anonymous authentication failed\n";
			$session->close();
			exit(1);
		}
	}
	return $session;
}

sub urldecode {
	my ($string) = @_;
	if (defined $string) {
		$string =~ tr/+/ /;
		$string =~ s/\%([0-9a-f]{2})/chr(hex($1))/gei;
	}
	return $string;
}

# vim: ts=4 ai
