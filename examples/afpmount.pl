#!/usr/bin/env perl

# imports {{{1
use Fuse qw(:xattr);			# preferably use Fuse 0.09_3 (or later), for
								# decent support of files >= 2**31 bytes long
use Net::AFP::Connection::TCP;	# the class which actually sets up and
								# handles the guts of talking to an AFP
								# server via TCP/IP
use Net::AFP::Result;			# AFP result codes
use Net::AFP::VolAttrs;			# volume attribute definitions
use Net::AFP::VolParms;			# parameters for FPOpenVol()
use Net::AFP::UAMs;				# User Auth Method helper code
use Net::AFP::Versions;			# version checking/agreement helper code
use Encode;						# handle encoding/decoding strings
use Socket;						# for socket related constants for
								# parent/child IPC code

# Conditionally include Term::ReadPassword; it doesn't need to be present
# for supplying passwords via the AFP URL directly, but it's needed for
# prompting.
my $has_Term_ReadPassword = 1;
eval { require Term::ReadPassword; };
if ($@) { $has_Term_ReadPassword = 0; }

my $has_Data_UUID = 1;
eval { require Data::UUID; };
if ($@) { $has_Data_UUID = 0; }

use Getopt::Long;				# for parsing command line options
use POSIX qw(EACCES EBADF EBUSY EEXIST EINVAL EISDIR EMFILE ENODEV
			 ENOENT ENOSPC ENOSYS ENOTDIR ENOTEMPTY EPERM EROFS ESPIPE
			 ETXTBSY EOPNOTSUPP EIO O_RDONLY O_WRONLY O_RDWR O_ACCMODE);
use Fcntl qw(:mode);			# macros and constants related to symlink
								# checking code
sub ENODATA() { return 61; }	# need this error constant for extended
								# attribute operations

use Data::Dumper;				# for diagnostic output when debugging is on

use strict;
use warnings;
# }}}1

# define constants {{{1
use constant MSG_NEEDPASSWORD	=> 1;
use constant MSG_PASSWORDIS		=> 2;
use constant MSG_RUNNING		=> 3;
use constant MSG_STARTERR		=> 4;
use constant MSGFORMAT			=> 'CS';
use constant MSGLEN				=> 3;
my @msgfields = ('msg', 'payloadlen');

# How much write data can we buffer locally before flushing to the server?
use constant COALESCE_MAX		=> 131072;

# What character encoding we should be pushing out to the virtual filesystem
# for paths? This is it.
use constant ENCODING			=> 'utf8';

# Special magic extended attribute names to take advantage of certain
# AFP features.
use constant ACL_XATTR			=> 'system.afp_acl';
use constant COMMENT_XATTR		=> 'system.comment';
# }}}1

# define globals {{{1
my $topDirID = 2;
my $currVolID = undef;
my $afpSession = undef;
my $DTRefNum = undef;

# open fork numbers for files that have been opened via afp_open()
our %ofilecache = ();

# Set up the pattern to use for breaking the AFP URL into its components.
my $ipv4_byte	= '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2(?:[0-4][0-9]|5[0-5]))';
my $v6grp_p		= '[0-9a-f]{1,4}';
my @ipv6_patterns = (
		'(?:' . $v6grp_p . ':){7}(?:' . $v6grp_p . ')?',
		'(?:' . $v6grp_p . ')?:(?::' . $v6grp_p . '){1,6}',
		'(?:' . $v6grp_p . ':){2}(?::' . $v6grp_p . '){1,5}',
		'(?:' . $v6grp_p . ':){3}(?::' . $v6grp_p . '){1,4}',
		'(?:' . $v6grp_p . ':){4}(?::' . $v6grp_p . '){1,3}',
		'(?:' . $v6grp_p . ':){5}(?::' . $v6grp_p . '){1,2}',
		'(?:' . $v6grp_p . ':){6}:' . $v6grp_p,
		'(?:' . $v6grp_p . ':){1,6}:',
		# IPv4-in-IPv6 addressing style, with zero-fill
		'(?:0{1,4}:){5}(?:0|ffff):(?:' . $ipv4_byte . '\.){3}' . $ipv4_byte,
		# IPv4-in-IPv6 addressing style, without zero-fill
		'::(?:ffff:)?(?:' . $ipv4_byte . '\.){3}' . $ipv4_byte);
my $ipv6_pattern = join('|', @ipv6_patterns);

# FIXME: need to add IPv6 address handling to the AFP URL stuff...
my $afp_url_pattern = qr/^(afp):\/(at)?\/(?:([^:\@\/;]*)(?:;AUTH=([^:\@\/;]+))?(?::([^:\@\/;]*))?\@)?([^:\/\@;]+)(?::([^:\/\@;]+))?(?:\/(?:([^:\/\@;]+)(\/.*)?)?)?$/;
my @args = ('protocol', 'atalk_transport', 'username', 'UAM', 'password',
		'host', 'port', 'volume', 'subpath');
# }}}1

our $__AFP_DEBUG;
our $__DSI_DEBUG;
our $_DEBUG;

# Handle the command line args.
my %opts;
exit(&EINVAL) unless GetOptions('interactive'	=> \$opts{'i'},
								'debug-afp'		=> \$__AFP_DEBUG,
								'debug-dsi'		=> \$__DSI_DEBUG,
								'debug-self'	=> \$_DEBUG);

my($path, $mountpoint) = @ARGV;
my %values;

sub urldecode($) { # {{{1
	my ($string) = @_;
	if (defined $string) {
		$string =~ tr/+/ /;
		$string =~ s/\%([0-9a-f]{2})/chr(hex($1))/gei;
	}
	return $string;
} # }}}1

sub urlencode($) { # {{{1
	my ($string) = @_;
	if (defined $string) {
		$string =~ s/([^\w\/_\-. ])/sprintf('%%%02x',ord($1))/gei;
		$string =~ tr/ /+/;
	}
	return $string;
} # }}}1

@values{@args} = $path =~ $afp_url_pattern;
foreach (keys(%values)) { $values{$_} = urldecode($values{$_}); }
print Dumper(\%values) if defined $::_DEBUG;

# Check the necessary arguments to make sure we can actually do something.
die('Unable to extract host from AFP URL') unless defined $values{'host'};
die('Unable to extract volume from AFP URL') unless defined $values{'volume'};
die('AppleTalk transport not currently supported')
		if defined $values{'atalk_transport'};

# scrub arguments {{{1
my $scrubbed_url = $values{'protocol'} . '://';
if (defined $values{'username'}) {
	$scrubbed_url .= urlencode($values{'username'}) . '@';
}
$scrubbed_url .= urlencode($values{'host'});
if (defined $values{'port'}) {
	$scrubbed_url .= ':' . urlencode($values{'port'});
}
$scrubbed_url .= '/';
if (defined $values{'volume'}) {
	$scrubbed_url .= urlencode($values{'volume'});
	if (defined $values{'subpath'}) {
		$scrubbed_url .= urlencode($values{'subpath'});
	}
}

my $script_name = $0;
$0 = join(' ', $script_name, $scrubbed_url, $mountpoint);
# }}}1

unless (-d $mountpoint) {
	print STDERR "ERROR: attempted to mount to non-directory\n";
	exit(&ENOTDIR) 
}

# make the parent process into a really simple rpc server that handles
# messages from the actual client process (which will go into the
# background), for things like getting the user's password.
# parent IPC {{{1
socketpair(CHILD, PARENT, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
		or die("socketpair() failed: $!");
my $pid = fork();
die("fork() failed: $!") unless defined($pid);
if ($pid > 0) {
	# parent process; we want the child to become independent, but first we
	# have to hang around until it's running happily.
	close(PARENT);

	while (1) {
		my $rin = '';
		my $ein = '';
		vec($rin, fileno(CHILD), 1) = 1;
		my($eout, $rout);
		select($rout = $rin, undef, $eout = $ein, 1);
		if ($rout) {
			# process received message {{{2
			my $data = '';
			sysread(CHILD, $data, MSGLEN);
			my %msg;
			@msg{@msgfields} = unpack(MSGFORMAT, $data);
			my $payload;
			if ($msg{'payloadlen'}) {
				sysread(CHILD, $payload, $msg{'payloadlen'});
			}

			if ($msg{'msg'} == MSG_RUNNING) {
				# the child process has said everything's happy, so we can
				# now go away; it could still implode, but it's now to a
				# point where we can't do anything about it.
				exit(0);
			} elsif ($msg{'msg'} == MSG_STARTERR) {
				# some sort of failure condition occurred.
				my $failcode = unpack('s', $payload);
				exit($failcode);
			} elsif ($msg{'msg'} == MSG_NEEDPASSWORD) {
				# child process needs a password, so we'll do the prompting
				# for it.
				my $prompt = 'Password for ' . $values{'username'} .
						' at ' . $values{'host'} . ': ';
				my $pw = '';
				if ($has_Term_ReadPassword) {
					$pw = Term::ReadPassword::read_password($prompt);
				} else {
					print "Term::ReadPassword was not available, can't ",
							"get password\n";
				}
				syswrite(CHILD, pack(MSGFORMAT, MSG_PASSWORDIS,
						length($pw)) . $pw);
			} else {
				# this should never happen...
				print "unknown message received?\n";
				exit(1);
			} # }}}2
		}
		if ($eout) {
			# this should never happen...
			print "unknown socket failure occurred, aborting\n";
			exit(1);
		}
	}

	# this should never happen...
	exit(1);
} # }}}1
close(CHILD);

# Use FPGetSrvrInfo() to get some initial information about the server for
# use later in the connection process.
# get server information {{{1
my $srvInfo;
my $rc = Net::AFP::Connection::TCP->FPGetSrvrInfo(@values{'host', 'port'},
		\$srvInfo);
if ($rc != Net::AFP::Result::kFPNoErr) {
	print "Could not issue FPGetSrvrInfo on ", $values{'host'}, "\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
	exit(1);
}
print Dumper($srvInfo) if defined $::_DEBUG;
# }}}1

# Actually open a session to the server.
# open server connection {{{1
$afpSession = new Net::AFP::Connection::TCP(@values{'host', 'port'});
unless (ref($afpSession) ne '' and $afpSession->isa('Net::AFP::Connection')) {
	print "Could not connect via AFP to ", $values{'host'}, "\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
	exit(1);
}
# }}}1

# Hook the tail of the execution path to close the connection properly, rather
# than having to do it again and again.
# hook program exit {{{1
sub END {
	if (defined $afpSession) {
		$afpSession->FPCloseDT($DTRefNum) if defined $DTRefNum;
		$afpSession->FPCloseVol($currVolID) if defined $currVolID;
		$afpSession->FPLogout();
		$afpSession->close();
	}
} # }}}1

# Establish which AFP protocol version the server has in common with us.
# Abort if (by chance) we can't come to an agreement.
# version agreement {{{1
my $commonVersion = Net::AFP::Versions::GetPreferredVersion(
		$$srvInfo{'AFPVersions'});
if (!defined $commonVersion) {
	print "Couldn't agree on an AFP protocol version with the server\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
	exit(1);
}
# }}}1

# Authenticate with the server.
# do authentication {{{1
if (defined $values{'username'}) {
	my $uamList = $$srvInfo{'UAMs'};
	if (defined $values{'UAM'}) {
		$uamList = [ $values{'UAM'} ];
	}
	my $rc = Net::AFP::UAMs::PasswordAuth($afpSession, $commonVersion,
			$uamList, $values{'username'}, sub {
				if (!defined $values{'password'} && defined $opts{'i'}) {
					syswrite(PARENT, pack(MSGFORMAT, MSG_NEEDPASSWORD, 0));
					my($rin, $rout, $data, $payload, %msg) =
							('', undef, '', '');
					vec($rin, fileno(PARENT), 1) = 1;
					select($rout = $rin, undef, undef, 0);
					sysread(PARENT, $data, MSGLEN);
					@msg{@msgfields} = unpack(MSGFORMAT, $data);
					if ($msg{'payloadlen'} > 0) {
						sysread(PARENT, $payload, $msg{'payloadlen'});
					}
					$values{'password'} = $payload;
				}
				unless (defined $values{'password'}) {
					$values{'password'} = '';
				}
				return $values{'password'};
			});
	unless ($rc == Net::AFP::Result::kFPNoErr) {
		print "Incorrect username/password while trying to authenticate\n";
		syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &EACCES));
		exit(1);
	}
} else {
	# do anonymous auth to the AFP server instead
	my $rc = Net::AFP::UAMs::GuestAuth($afpSession, $commonVersion);
	unless ($rc == Net::AFP::Result::kFPNoErr) {
		print "Anonymous authentication to server failed (maybe no ",
				"guest auth allowed?)\n";
		syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &EACCES));
		exit(1);
	}
} # }}}1

# Open the volume indicated at start time, and abort if the server bitches
# at us.
# open volume {{{1
my $volInfo;
$rc = $afpSession->FPOpenVol(Net::AFP::VolParms::kFPVolAttributeBit |
		Net::AFP::VolParms::kFPVolSignatureBit, $values{'volume'}, undef,
		\$volInfo);
if ($rc == Net::AFP::Result::kFPAccessDenied) {
	# no volume password; does apple's AFP server even support volume
	# passwords anymore? I don't really know.
	print "Server expected volume password\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &EACCES));
	exit(1);
} elsif ($rc == Net::AFP::Result::kFPObjectNotFound ||
		$rc == Net::AFP::Result::kFPParamErr) {
	# Server didn't know the volume we asked for.
	print 'Volume "', $values{'volume'}, "\" does not exist on server\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
	exit(1);
} elsif ($rc != Net::AFP::Result::kFPNoErr) {
	# Some other error occurred; if the docs are to be believed, this should
	# never happen unless we pass bad flags (coding error) or some
	# non-AFP-specific condition causes a failure (which is out of our
	# hands)...
	print 'FPOpenVol failed with error ', $rc, ' (',
			Net::AFP::Result::strerror($rc), ")\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
	exit(1);
}
print Dumper($volInfo) if defined $::_DEBUG;

if ($$volInfo{'Signature'} == 3) {
	print "Volume uses variable Directory IDs; not currently supported\n";
	syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &EINVAL));
	exit(1);
}

$currVolID = $$volInfo{'ID'};
# Copy out the attribute value, since there are some flags we should really
# be checking in there (you know, for UTF8 support, extended attributes,
# ACLs, things like that)...
my $volAttrs = $$volInfo{'VolAttribute'};

my $pathType	= 2; # AFP long names by default
my $pathFlag	= Net::AFP::FileParms::kFPLongNameBit;
my $pathkey		= 'LongName';

if ($volAttrs & Net::AFP::VolAttrs::kSupportsUTF8Names) {
	# If the remote volume does UTF8 names, then we'll go with that..
	$pathType		= 3;
	$pathFlag		= Net::AFP::FileParms::kFPUTF8NameBit;
	$pathkey		= 'UTF8Name';
}

my $DForkLenFlag	= Net::AFP::FileParms::kFPDataForkLenBit;
my $DForkLenKey		= 'DataForkLen';
my $UseExtOps		= 0;
# I *think* large file support entered the picture as of AFP 3.0...
if (Net::AFP::Versions::CompareByVersionNum($afpSession, 3, 0,
				Net::AFP::Versions::AtLeast)) {
	$DForkLenFlag	= Net::AFP::FileParms::kFPExtDataForkLenBit;
	$DForkLenKey	= 'ExtDataForkLen';
	$UseExtOps		= 1;
}

# Not checking the return code here. If this fails, $DTRefNum won't be
# defined, so we don't need to worry about possible later unpredictable
# failures due to this.
$afpSession->FPOpenDT($currVolID, \$DTRefNum);

my $client_uuid;
if ($volAttrs & Net::AFP::VolAttrs::kSupportsACLs) {
    if ($has_Data_UUID) {
	    my $uo = new Data::UUID;
	    $client_uuid = $uo->create();
    } else {
	    print "Need Data::UUID class for full ACL functionality, ACL checking disabled\n";
    }
}
# }}}1

# If a subpath is defined, find the node ID for the directory, and use that
# as the root; if the node isn't found or is not a directory, then abort.
# lookup node ID for subpath mount {{{1
if (defined $values{'subpath'}) {
	print 'Looking up directory \'', $values{'subpath'},
			"' as pivot point for root node\n" if defined $::_DEBUG;
	my $realDirPath = translate_path($values{'subpath'});
	my $dirBitmap = Net::AFP::DirParms::kFPNodeIDBit;
	
	my $resp;
	my $rc = $afpSession->FPGetFileDirParms($currVolID, $topDirID, $dirBitmap,
			$dirBitmap, $pathType, $realDirPath, \$resp);
	
	if ($rc != Net::AFP::Result::kFPNoErr || !exists $$resp{'NodeID'}) {
		print STDERR "ERROR: Specified directory not found\n";
		syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENODEV));
		exit(1);
	}

	if ($$resp{'FileIsDir'} != 1) {
		print STDERR "ERROR: Attempted to pivot mount root to non-directory\n";
		syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, &ENOTDIR));
		exit(1);
	}
	$topDirID = $$resp{'NodeID'};
	print "Mount root node ID changed to $topDirID\n" if defined $::_DEBUG;
} # }}}1

# Send a love note to the folks saying "wish you were here, everything's
# fine".
syswrite(PARENT, pack(MSGFORMAT, MSG_RUNNING, 0));
close(PARENT);

# Close all FDs.
#for (my $i = 0; $i < 1024; $i++) {
#	open(HANDLE, '<&=', $i);
#	close(HANDLE);
#}
# reopen the standard FDs onto /dev/null; they have to be open, since if
# anything writes to the default FDs after they get opened to by something
# else, things can break badly.
#open(STDIN, '<', '/dev/null');
#open(STDOUT, '>', '/dev/null');
#open(STDERR, '>&', \*STDOUT);

# call FUSE main loop {{{1
Fuse::main( 'mountpoint'	=> $mountpoint,
			'mountopts'		=> 'allow_other',
			'getattr'		=> \&afp_getattr,
			'readlink'		=> \&afp_readlink,
			'getdir'		=> \&afp_getdir,
			'mknod'			=> \&afp_mknod,
			'mkdir'			=> \&afp_mkdir,
			'unlink'		=> \&afp_unlink,
			'rmdir'			=> \&afp_unlink,
			'symlink'		=> \&afp_symlink,
			'rename'		=> \&afp_rename,
			'link'			=> \&afp_link,
			'chmod'			=> \&afp_chmod,
			'chown'			=> \&afp_chown,
			'truncate'		=> \&afp_truncate,
			'utime'			=> \&afp_utime,
			'open'			=> \&afp_open,
			'read'			=> \&afp_read,
			'write'			=> \&afp_write,
			'statfs'		=> \&afp_statfs,
			'flush'			=> \&afp_flush,
			'release'		=> \&afp_release,
			'fsync'			=> \&afp_fsync,
			'setxattr'		=> \&afp_setxattr,
			'getxattr'		=> \&afp_getxattr,
			'listxattr'		=> \&afp_listxattr,
			'removexattr'	=> \&afp_removexattr,
		); # }}}1

# If we reach this point, the FUSE mountpoint has been released, so exit
# quietly...
exit(0);

sub afp_getattr { # {{{1
	my($file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my ($rc, $resp) = lookup_afp_entry($fileName);
	return $rc if $rc != Net::AFP::Result::kFPNoErr;

	return -&ENOENT if $$resp{'NodeID'} == 0;

	# assemble stat record {{{2
	my @stat = (
		# device number (just make it 0, since it's not a real device)
		0,
		# inode number (node ID works fine)
		$resp->{'NodeID'},
		# permission mask
		exists($$resp{'UnixPerms'}) ? $$resp{'UnixPerms'} :
				($$resp{'FileIsDir'} ? 040755 : 0100644),
		# link count
		#$resp->{'FileIsDir'} ? $$resp{'OffspringCount'} + 2 : 1,
		$resp->{'FileIsDir'} ? 2 : 1,
		# UID number
		exists($resp->{'UnixUID'}) ? $$resp{'UnixUID'} : 0,
		# GID number
		exists($resp->{'UnixGID'}) ? $$resp{'UnixGID'} : 0,
		# device special major/minor number
		0,
		# file size in bytes
		$$resp{'FileIsDir'} ? 4096 : $$resp{$DForkLenKey},
		# last accessed time
		$$resp{'ModDate'},
		# data modified time
		$$resp{'ModDate'},
		# inode changed time
		$$resp{'CreateDate'},
		# preferred block size
		512,
		# size in blocks
		$$resp{'FileIsDir'} ? 1 : int(($$resp{$DForkLenKey} - 1) / 512) + 1
	);
	# }}}2
	return(@stat);
} # }}}1

sub afp_readlink { # {{{1
	my($file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	# Classic MacOS' concept of an "alias", so far as I can tell, doesn't
	# really translate to the UNIX concept of a symlink; I might be able
	# to implement it later via file IDs, but until then, if UNIX permissions
	# aren't present, this won't work.
	return -&EINVAL unless $volAttrs & Net::AFP::VolAttrs::kSupportsUnixPrivs;

	$file = decode(ENCODING, $file);
	# Break the provided path down into a directory ID and filename.
	my $fileName = translate_path($file);

	# Get the UNIX privilege info for the file.
	my $fileBitmap = Net::AFP::FileParms::kFPUnixPrivsBit;
	my $resp;
	my $rc = $afpSession->FPGetFileDirParms($currVolID, $topDirID, $fileBitmap,
			0, $pathType, $fileName, \$resp);
	return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

	# The UNIX privilege info is pretty universal, so just use the standard
	# macros to see if the permissions show it to be a symlink.
	# process symlink {{{2
	if (S_ISLNK($resp->{'UnixPerms'})) {
		# Now we have to open the "data fork" of this pseudo-file, read the
		# "contents" (a single line containing the path of the symbolic link),
		# and return that.
		my $sresp;
		$rc = $afpSession->FPOpenFork(0, $currVolID, $topDirID, 0, 0x1,
				$pathType, $fileName, \$sresp);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
		return -&EMFILE if $rc == Net::AFP::Result::kFPTooManyFilesOpen;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		
		my $linkPath;
		my $pos = 0;
		do {
			my $readText;
			if ($UseExtOps) {
				$rc = $afpSession->FPReadExt($$sresp{'OForkRefNum'}, $pos,
						1024, \$readText);
			} else {
				$rc = $afpSession->FPRead($$sresp{'OForkRefNum'}, $pos, 1024,
						undef, undef, \$readText);
			}
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&EINVAL unless $rc == Net::AFP::Result::kFPNoErr or
					$rc == Net::AFP::Result::kFPEOFErr;
			$linkPath .= $readText;
		} until ($rc == Net::AFP::Result::kFPEOFErr);
		$afpSession->FPCloseFork($sresp->{'OForkRefNum'});
		return encode(ENCODING, $linkPath);
	} # }}}2

	return -&EINVAL;
} # }}}1

sub afp_getdir { # {{{1
	my($dirname) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$dirname = decode(ENCODING, $dirname);
	my $fileName = translate_path($dirname);
	my @filesList = ('.', '..');

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_LIST_DIRECTORY,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	my $resp;
	# Set the result set size limit; if there are more entries in the
	# directory, extra requests will have to be sent. Larger set sizes
	# mean less time spent waiting around for responses.
	my $setsize = 500;
	my @arglist = ($currVolID, $topDirID, $pathFlag, $pathFlag, $setsize, 1,
			32767, $pathType, $fileName, \$resp);
	my $rc = undef;
	# loop reading entries {{{2
	while (1) {
		$rc = $afpSession->FPEnumerateExt2(@arglist);
		if ($rc == Net::AFP::Result::kFPCallNotSupported) {
			$rc = $afpSession->FPEnumerateExt(@arglist);
			if ($rc == Net::AFP::Result::kFPCallNotSupported) {
				$rc = $afpSession->FPEnumerate(@arglist);
			}
		}

		last unless $rc == Net::AFP::Result::kFPNoErr;

		# Under some circumstances (no, this is not an error elsewhere in
		# my code, near as I can tell) on a second swipe, we'll get *one*
		# dirent back, which is a file we already got. that means that's
		# the end.
		if ($arglist[5] > 1 &&
				($$resp[0]{$pathkey} eq $filesList[$#filesList])) {
			shift(@$resp);
			$arglist[5]++;
		}
		# anyone actually trying to readdir() gets the entries in reverse
		# order, for some odd reason; bug in FUSE driver/libfuse/Fuse module?
		push(@filesList, map {
						my $name = $_->{$pathkey};
						$name =~ tr/\//:/;
						encode(ENCODING, $name); } @$resp);

		# Set up for a subsequent call to get directory entries.
		$arglist[5] += scalar(@$resp);
		undef $resp;
	}
	# }}}2
	if ($rc == Net::AFP::Result::kFPObjectNotFound or
			$rc == Net::AFP::Result::kFPNoErr) {
		return(reverse(@filesList), 0);
	}
	return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT  if $rc == Net::AFP::Result::kFPDirNotFound;
	return -&ENOTDIR if $rc == Net::AFP::Result::kFPObjectTypeErr;
	return -&EINVAL  if $rc == Net::AFP::Result::kFPParamErr;
	return -&EACCES;
}
# }}}1

sub afp_mknod { # {{{1
	my ($file, $mode, $devnum) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	if (S_ISREG($mode)) {
		my ($rc, $resp) = lookup_afp_entry(path_parent($fileName));
		return $rc if $rc != Net::AFP::Result::kFPNoErr;
		if (defined $client_uuid) {
			my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
					$client_uuid, Net::AFP::ACL::KAUTH_VNODE_ADD_FILE,
					$pathType, path_parent($fileName));
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
			return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		}

		$rc = $afpSession->FPCreateFile(0, $currVolID, $resp->{'NodeID'},
				 $pathType, node_name($fileName));
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOSPC if $rc == Net::AFP::Result::kFPDiskFull;
		return -&EBUSY  if $rc == Net::AFP::Result::kFPFileBusy;
		return -&EEXIST if $rc == Net::AFP::Result::kFPObjectExists;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
		return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	}
	return -&EOPNOTSUPP;
} # }}}1

sub afp_mkdir { # {{{1
	my ($file, $mode) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my $newDirID;
	my ($rc, $resp) = lookup_afp_entry(path_parent($fileName));
	return $rc if $rc != Net::AFP::Result::kFPNoErr;
	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_ADD_SUBDIRECTORY,
				$pathType, path_parent($fileName));
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	$rc = $afpSession->FPCreateDir($currVolID, $resp->{'NodeID'}, $pathType,
			node_name($fileName), \$newDirID);
	return 0		if $rc == Net::AFP::Result::kFPNoErr;
	return -&EPERM	if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOSPC	if $rc == Net::AFP::Result::kFPDiskFull;
	return -&EPERM	if $rc == Net::AFP::Result::kFPFlatVol;
	return -&ENOENT	if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EEXIST	if $rc == Net::AFP::Result::kFPObjectExists;
	return -&EINVAL	if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS	if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF;
} # }}}1

sub afp_unlink { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	my ($file) = @_;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my ($rc, $resp) = lookup_afp_entry(path_parent($fileName));
	return $rc if $rc != Net::AFP::Result::kFPNoErr;

	if (exists $ofilecache{$fileName}) {
		$afpSession->FPCloseFork($ofilecache{$fileName}{'refnum'});
		delete $ofilecache{$fileName};
	}

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_DELETE, $pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	# don't have to worry about checking to ensure we're 'rm'ing a file;
	# this works for both, verifying that "unlink" is being invoked on a
	# non-directory is done elsewhere. also, we're referencing this sub
	# as the implementation for rmdir as well, which should work just fine
	# since the same backend call does both.
	$rc = $afpSession->FPDelete($currVolID, $resp->{'NodeID'}, $pathType,
			node_name($fileName));
	return 0			if $rc == Net::AFP::Result::kFPNoErr;
	return -&EACCES		if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&EBUSY		if $rc == Net::AFP::Result::kFPFileBusy;
	return -&EBUSY		if $rc == Net::AFP::Result::kFPObjectLocked;
	return -&ENOENT		if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EISDIR		if $rc == Net::AFP::Result::kFPObjectTypeErr;
	return -&EINVAL		if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS		if $rc == Net::AFP::Result::kFPVolLocked;
	return -&ENOTEMPTY	if $rc == Net::AFP::Result::kFPDirNotEmpty;
	return -&EBADF;
} # }}}1

# seems OS X 10.4 causes the newly created symlink to be locked, so once
# you create it, you can't remove it via AFP until you unmount the volume
# once. good work apple. :| doesn't happen on netatalk or OS X 10.5.
sub afp_symlink { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	my($target, $linkname) = @_;

	return -&EPERM unless $volAttrs & Net::AFP::VolAttrs::kSupportsUnixPrivs;

	$linkname = decode(ENCODING, $linkname);
	my $fileName = translate_path($linkname);

	# FIXME: add FPAccess() check
	
	# create the target file first
	# create target file {{{2
	my $rc = $afpSession->FPCreateFile(0, $currVolID, $topDirID, $pathType,
			$fileName);
	return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOSPC if $rc == Net::AFP::Result::kFPDiskFull;
	return -&EBUSY  if $rc == Net::AFP::Result::kFPFileBusy;
	return -&EEXIST if $rc == Net::AFP::Result::kFPObjectExists;
	return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	# }}}2

	# open the file, and write out the path given as the link target...
	# open and write link target {{{2
	my $resp;
	$rc = $afpSession->FPOpenFork(0, $currVolID, $topDirID, 0, 0x3, $pathType,
			$fileName, \$resp);
	return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ETXTBSY if $rc == Net::AFP::Result::kFPDenyConflict;
	return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EACCES  if $rc == Net::AFP::Result::kFPObjectLocked;
	return -&EISDIR  if $rc == Net::AFP::Result::kFPObjectTypeErr;
	return -&EINVAL  if $rc == Net::AFP::Result::kFPParamErr;
	return -&EMFILE  if $rc == Net::AFP::Result::kFPTooManyFilesOpen;
	return -&EROFS   if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
	my $forkID = $resp->{'OForkRefNum'};

	my $lastWritten;
	if ($UseExtOps) {
		$rc = $afpSession->FPWriteExt(0, $forkID, 0, length($target), $target,
				\$lastWritten);
	} else {
		$rc = $afpSession->FPWrite(0, $forkID, 0, length($target), $target,
				\$lastWritten);
	}

	$afpSession->FPCloseFork($forkID);

	return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOSPC  if $rc == Net::AFP::Result::kFPDiskFull;
	return -&ETXTBSY if $rc == Net::AFP::Result::kFPLockErr;
	return -&EINVAL  if $rc == Net::AFP::Result::kFPParamErr;
	return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
	# }}}2

	# set finder info {{{2
	my $bitmap = Net::AFP::FileParms::kFPFinderInfoBit |
			Net::AFP::FileParms::kFPModDateBit;

	# apparently this is the magic to transmute a file into a symlink...
	$rc = $afpSession->FPSetFileParms($currVolID, $topDirID, $bitmap, $pathType,
			$fileName, 'FinderInfo' => 'slnkrhap', 'ModDate' => time());
	
	return 0		if $rc == Net::AFP::Result::kFPNoErr;
	return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
	return -&EBADF;
	# }}}2

} # }}}1

sub afp_rename { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	my ($oldName, $newName) = @_;

	$oldName = decode(ENCODING, $oldName);
	$newName = decode(ENCODING, $newName);
	my @elems = split(/\//, $newName);
	my $newPath = join('/', @elems[0 .. ($#elems - 1)]);
	if ($newPath eq '') {
		$newPath = '/';
	}
	my $newRealName = $elems[$#elems];
	@elems = split(/\//, $oldName);
	my $oldRealName = $elems[$#elems];

	my $oldXlated = translate_path($oldName);
	my $newXlated = translate_path($newPath);
	
	my ($rc, $old_stat) = lookup_afp_entry($oldXlated, 1);
	return $rc if $rc != Net::AFP::Result::kFPNoErr;
	my $new_stat;
	($rc, $new_stat) = lookup_afp_entry($newXlated);
	return $rc if $rc != Net::AFP::Result::kFPNoErr;

	# FIXME: add FPAccess() check

	my @arglist;
	my $resp;
	if ($old_stat->{'FileIsDir'} == 1) {
		@arglist = ($currVolID, $old_stat->{'ParentDirID'},
				$new_stat->{'NodeID'}, $pathType, $oldRealName,
				$pathType, '', $pathType, $newRealName, \$resp);
	} else {
		@arglist = ($currVolID, $old_stat->{'ParentDirID'},
				$new_stat->{'NodeID'}, $pathType, $oldRealName, $pathType, '',
				$pathType, $newRealName, \$resp);
	}
	$rc = $afpSession->FPMoveAndRename(@arglist);

	if ($rc == Net::AFP::Result::kFPObjectExists) {
		$afpSession->FPDelete($currVolID, $new_stat->{'NodeID'}, $pathType,
				$newRealName);
		$rc = $afpSession->FPMoveAndRename(@arglist);
	}
	if ($rc == Net::AFP::Result::kFPNoErr) {
        # Move the open filehandle for the renamed file to the new name,
        # if there is one.
        if (exists $ofilecache{$oldXlated}) {
            $ofilecache{$newXlated} = $ofilecache{$oldXlated};
            delete $ofilecache{$oldXlated};
        }
        return 0;
    }
	return -&EACCES	if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&EINVAL	if $rc == Net::AFP::Result::kFPCantMove;
	return -&EBUSY	if $rc == Net::AFP::Result::kFPObjectLocked;
	return -&ENOENT	if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL	if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS	if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF;
} # }}}1

sub afp_link { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	return -&EOPNOTSUPP;
} # }}}1

sub afp_chmod { # {{{1
	my ($file, $mode) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	
	my $fileName = translate_path(decode(ENCODING, $file));
	my ($rc, $resp) = lookup_afp_entry($fileName, 1);
	return $rc if $rc != Net::AFP::Result::kFPNoErr;

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_WRITE_ATTRIBUTES,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	$rc = $afpSession->FPSetFileDirParms($currVolID, $topDirID,
			Net::AFP::FileParms::kFPUnixPrivsBit, $pathType, $fileName,
			'UnixPerms'			=> $mode | S_IFMT($resp->{'UnixPerms'}),
			'UnixUID'			=> $resp->{'UnixUID'},
			'UnixGID'			=> $resp->{'UnixGID'},
			'UnixAccessRights'	=> $resp->{'UnixAccessRights'});
	return -&EPERM  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

	return 0;
} # }}}1

sub afp_chown { # {{{1
	my($file, $uid, $gid) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	my $fileName = translate_path(decode(ENCODING, $file));
	my ($rc, $resp) = lookup_afp_entry($fileName, 1);
	return $rc if $rc != Net::AFP::Result::kFPNoErr;

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_CHANGE_OWNER,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	$rc = $afpSession->FPSetFileDirParms($currVolID, $topDirID,
			Net::AFP::FileParms::kFPUnixPrivsBit, $pathType, $fileName,
			'UnixPerms'			=> $resp->{'UnixPerms'},
			'UnixUID'			=> $uid,
			'UnixGID'			=> $gid,
			'UnixAccessRights'	=> $resp->{'UnixAccessRights'});
	return -&EPERM  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

	return 0;
} # }}}1

sub afp_truncate { # {{{1
	my ($file, $length) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	my $ofork;
	my $close_fork = 0;

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_WRITE_DATA,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	my $rc;
	if (exists $ofilecache{$fileName}) {
		$ofork = $ofilecache{$fileName}{'refnum'};
	} else {
		my $resp;
		$rc = $afpSession->FPOpenFork(0, $currVolID, $topDirID, 0, 0x3,
				$pathType, $fileName, \$resp);
		return -&EPERM  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&EPERM  if $rc == Net::AFP::Result::kFPDenyConflict;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EPERM  if $rc == Net::AFP::Result::kFPObjectLocked;
		return -&EISDIR if $rc == Net::AFP::Result::kFPObjectTypeErr;
		return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
		return -&EMFILE if $rc == Net::AFP::Result::kFPTooManyFilesOpen;
		return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

		$ofork = $$resp{'OForkRefNum'};
		$close_fork = 1;
	}

	$rc = $afpSession->FPSetForkParms($ofork,
			$DForkLenFlag, $length);

	$afpSession->FPCloseFork($ofork) if $close_fork == 1;

	return 0		if $rc == Net::AFP::Result::kFPNoErr;
	return -&EPERM  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOSPC if $rc == Net::AFP::Result::kFPDiskFull;
	return -&EPERM  if $rc == Net::AFP::Result::kFPLockErr;
	return -&EINVAL if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS  if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF;
} # }}}1

sub afp_utime { # {{{1
	my ($file, $actime, $modtime) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my $rc = $afpSession->FPSetFileDirParms($currVolID, $topDirID,
			Net::AFP::FileParms::kFPCreateDateBit | Net::AFP::FileParms::kFPModDateBit,
			$pathType, $fileName, 'CreateDate' => $actime,
			'ModDate' => $modtime);
	return 0		if $rc == Net::AFP::Result::kFPNoErr;
	return -&EPERM	if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT	if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL	if $rc == Net::AFP::Result::kFPParamErr;
	return -&EROFS	if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF;
} # }}}1

sub afp_open { # {{{1
	my($file, $mode) = @_;
	print 'called ', (caller(0))[3], "('", $file, "', ", $mode, ")\n"
			if defined $::_DEBUG;

	my $refcount = 0;
	my $file_u = $file;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my $accessBitmap = 0x1;
	if (($mode & O_ACCMODE) == O_RDWR) {
		$accessBitmap = 0x3;
	} elsif (($mode & O_ACCMODE) == O_WRONLY) {
		$accessBitmap = 0x2;
	} elsif (($mode & O_ACCMODE) == O_RDONLY) {
		$accessBitmap = 0x1;
	}

	# Speaking of being lied to, fuse claims release() doesn't get called
	# until the last reference goes away. Um... not so much really. It
	# happily closes and reopens filehandles mid-stream. This really
	# breaks the model. Fortunately a little refcounting fixes it
	# right up...
	if (exists $ofilecache{$fileName}) {
		my $cachedBitmap = $ofilecache{$fileName}{'mode'};
		if (($cachedBitmap & $accessBitmap) == $cachedBitmap) {
			$ofilecache{$fileName}{'refcount'}++;
			return 0;
		}
		afp_flush($file_u);
		$refcount = $ofilecache{$fileName}{'refcount'};
		my $rc = $afpSession->FPCloseFork($ofilecache{$fileName}{'refnum'});
		delete $ofilecache{$fileName};
		$accessBitmap = 0x3;
	}

	my $resp;
	my $rc = $afpSession->FPOpenFork(0, $currVolID, $topDirID, 0,
			$accessBitmap, $pathType, $fileName, \$resp);
	if ($rc == Net::AFP::Result::kFPNoErr) {
		$ofilecache{$fileName} = {
				'ostamp'			=> time(),
				'astamp'			=> time(),
				'mode'				=> $accessBitmap,
				'refnum'			=> $resp->{'OForkRefNum'},
				'coalesce_offset'	=> undef,
				'coalesce_len'		=> undef,
				'coalesce_buf'		=> "\0" x COALESCE_MAX,
				'refcount'			=> $refcount + 1 };
		return(0);
	}
	return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ETXTBSY if $rc == Net::AFP::Result::kFPDenyConflict;
	return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EACCES  if $rc == Net::AFP::Result::kFPObjectLocked;
	return -&EISDIR  if $rc == Net::AFP::Result::kFPObjectTypeErr;
	return -&EINVAL  if $rc == Net::AFP::Result::kFPParamErr;
	return -&EMFILE  if $rc == Net::AFP::Result::kFPTooManyFilesOpen;
	return -&EROFS   if $rc == Net::AFP::Result::kFPVolLocked;
	return -&EBADF;
} # }}}1

sub afp_read { # {{{1
	my($file, $len, $off) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	afp_fsync($file);

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	return -&EBADF unless exists $ofilecache{$fileName};

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_READ_DATA,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	my $forkID = $ofilecache{$fileName}{'refnum'};
	$ofilecache{$fileName}{'astamp'} = time();
	my $resp;
	my $rc;
	if ($UseExtOps) {
		$rc = $afpSession->FPReadExt($forkID, $off, $len, \$resp);
	} else {
		$rc = $afpSession->FPRead($forkID, $off, $len, undef, undef, \$resp);
	}
	return $resp     if (($rc == Net::AFP::Result::kFPNoErr)
			|| ($rc == Net::AFP::Result::kFPEOFErr && defined($resp)));
	return -&ESPIPE  if $rc == Net::AFP::Result::kFPEOFErr;
	return -&EBADF   if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ETXTBSY if $rc == Net::AFP::Result::kFPLockErr;
	return -&EINVAL  if $rc == Net::AFP::Result::kFPParamErr;
	return -&EBADF;
} # }}}1

sub afp_write { # {{{1
	my ($file, $data, $offset) = @_;
	print 'called ', (caller(0))[3], "('", $file, "', [data], ", $offset, ")\n"
			if defined $::_DEBUG;

	my $file_u = $file;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	return -&EBADF unless exists $ofilecache{$fileName};

	my $of_ent = $ofilecache{$fileName};
	my $forkID = $$of_ent{'refnum'};
	$$of_ent{'astamp'} = time();

	# This code implements write coalescing. FUSE 2.8 is supposed to be
	# implementing it at the libfuse level, but for now, doing lots of
	# small writes sucks for performance. This allows lots of small writes
	# to be bundled into fewer, large writes, which means less time spent
	# waiting for remote calls to be processed and less protocol overhead
	# to do it. Haven't yet benched it, but sequential write performance
	# via wget is notably better - I can saturate my Internet connection
	# with a download while writing to an AFP volume now.

	# coalesce writes {{{2
	if (defined $$of_ent{'coalesce_offset'} &&
			$$of_ent{'coalesce_len'} >= COALESCE_MAX) {
		my $rv = afp_flush($file_u);
		if ($rv != 0) {
			return $rv;
		}
	}

	# FIXME: add FPAccess() check

	if (defined $$of_ent{'coalesce_offset'}) {
		if ($offset == ($$of_ent{'coalesce_offset'} +
				$$of_ent{'coalesce_len'})) {
			substr($$of_ent{'coalesce_buf'}, $$of_ent{'coalesce_len'},
                    length($data), $data);
			$$of_ent{'coalesce_len'} += length($data);
			return length($data);
		} else {
			my $rv = afp_flush($file_u);
			if ($rv != 0) {
				return $rv;
			}
		}
	} else {
		substr($$of_ent{'coalesce_buf'}, 0, length($data), $data);
		$$of_ent{'coalesce_len'} = length($data);
		$$of_ent{'coalesce_offset'} = $offset;
		return length($data);
	}
	# }}}2
	my $lastWritten;
	my $rc;
	if ($UseExtOps) {
		$rc = $afpSession->FPWriteExt(0, $forkID, $offset, length($data),
				$data, \$lastWritten);
	} else {
		$rc = $afpSession->FPWrite(0, $forkID, $offset, length($data), $data,
				\$lastWritten);
	}
	
	return length($data) if $rc == Net::AFP::Result::kFPNoErr;
	return -&EACCES		 if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOSPC		 if $rc == Net::AFP::Result::kFPDiskFull;
	return -&ETXTBSY	 if $rc == Net::AFP::Result::kFPLockErr;
	return -&EINVAL		 if $rc == Net::AFP::Result::kFPParamErr;
	return -&EBADF		 if $rc != Net::AFP::Result::kFPNoErr;
} # }}}1

sub afp_statfs { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	my $VolBitmap;
	my $bf_key;
	my $bt_key;
	my $blocksize = 512;
	if ($UseExtOps) {
		$VolBitmap |= Net::AFP::VolParms::kFPVolExtBytesFreeBit |
					  Net::AFP::VolParms::kFPVolExtBytesTotalBit |
					  Net::AFP::VolParms::kFPVolBlockSizeBit;
		$bf_key = 'ExtBytesFree';
		$bt_key = 'ExtBytesTotal';
	} else {
		$VolBitmap |= Net::AFP::VolParms::kFPVolBytesFreeBit |
					  Net::AFP::VolParms::kFPVolBytesTotalBit;
		$bf_key = 'BytesFree';
		$bt_key = 'BytesTotal';
	}
	my $resp;
	my $rc = $afpSession->FPGetVolParms($currVolID, $VolBitmap, \$resp);
	if (exists $$resp{'BlockSize'}) {
		$blocksize = $$resp{'BlockSize'};
	}
	my @statinfo = (
			# namelen (?)
			255,
			# file count; not really (we're lying here), but afp doesn't
			# keep an "existing files" count
			int($$resp{$bt_key} / $blocksize),
			# files_free count; lying again, but afp doesn't have a concept
			# of "free inodes" either, it's not aware of such stuff
			int($$resp{$bf_key} / $blocksize),
			# total blocks
			int($$resp{$bt_key} / $blocksize),
			# free blocks
			int($$resp{$bf_key} / $blocksize),
			# block size
			$blocksize);
	return(@statinfo);
} # }}}1

sub afp_flush { # {{{1
	my ($file) = @_;
	print 'called ', (caller(0))[3], "('", $file, "')\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	if (exists $ofilecache{$fileName}) {
		# This is the second (and critical) part of write coalescing -
		# flushing the writes out to the remote volume. I'm probably
		# implementing this in a rather naive fashion, but it works so
		# far...
		if (defined $ofilecache{$fileName}{'coalesce_offset'}) {
			my($forkID, $offset, $len) =
					@{$ofilecache{$fileName}}{'refnum', 'coalesce_offset',
											  'coalesce_len'};
            my $data_ref = \$ofilecache{$fileName}{'coalesce_buf'};
			my $lastwr;
			my $rc;
			if ($UseExtOps) {
				$rc = $afpSession->FPWriteExt(0, $forkID, $offset, $len,
                        $$data_ref, \$lastwr);
			} else {
				$rc = $afpSession->FPWrite(0, $forkID, $offset, $len,
                        $$data_ref, \$lastwr);
			}
			if ($lastwr < $offset + $len) {
				print "afp_flush(): truncated write in flush? wtf?\n";
				return -&EIO;
			}
			undef $ofilecache{$fileName}{'coalesce_offset'};
		}
	}

	return(0);
} # }}}1

sub afp_release { # {{{1
	my ($file, $mode) = @_;
	print 'called ', (caller(0))[3], "('", $file, "', ", $mode, ")\n"
			if defined $::_DEBUG;

	my $file_u = $file;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	if (exists $ofilecache{$fileName}) {
		# If the reference count is not 0, just play along.
		return(0) if --$ofilecache{$fileName}{'refcount'};
		afp_flush($file_u);
		$afpSession->FPCloseFork($ofilecache{$fileName}{'refnum'});
		delete $ofilecache{$fileName};
		return 0;
	}
	return -&EBADF;
} # }}}1

sub afp_fsync { # {{{1
	my ($file, $flags) = @_;
	print 'called ', (caller(0))[3], "('", $file, "')\n"
			if defined $::_DEBUG;

	return afp_flush($file);
} # }}}1

sub afp_setxattr { # {{{1
	my($file, $attr, $value, $flags) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	$value = decode(ENCODING, $value);

	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR &&
			defined($client_uuid)) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
				$client_uuid, Net::AFP::ACL::KAUTH_VNODE_WRITE_SECURITY,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

		# if either of the flags is present, apply extra checking for the
		# presence of an ACL.
		if ($flags) {
			my $resp;
			$rc = $afpSession->FPGetACL($currVolID, $topDirID,
					Net::AFP::ACL::kFileSec_ACL, 0, $pathType, $fileName,
					\$resp);
			if ($flags & XATTR_CREATE) {
				return -&EEXIST
						if $$resp{'Bitmap'} & Net::AFP::ACL::kFileSec_ACL;
			} elsif ($flags & XATTR_REPLACE) {
				return -&ENODATA
						unless $$resp{'Bitmap'} & Net::AFP::ACL::kFileSec_ACL;
			}
		}
	
		# unpack the ACL from the client, so we can structure it to be handed
		# up to the AFP server
		my($acl_flags, @acl_parts) = unpack('NS/(LS/aLL)', $value);
		my @entries;
		while (scalar(@acl_parts) > 0) {
			my $entry = {};
			my $bitmap = shift(@acl_parts);
			my $utf8name = decode_utf8(shift(@acl_parts));
			my($uuid, $rc);
			# do the appropriate type of name lookup based on the attributes
			# given in the bitmap field.
			if ($bitmap == Net::AFP::ACL::kFileSec_UUID) {
				$rc = $afpSession->FPMapName(
						Net::AFP::MapParms::kUTF8NameToUserUUID, $utf8name,
						\$uuid);
			} elsif ($bitmap == Net::AFP::ACL::kFileSec_GRPUUID) {
				$rc = $afpSession->FPMapName(
						Net::AFP::MapParms::kUTF8NameToGroupUUID, $utf8name,
						\$uuid);
			} else {
				$rc = $afpSession->FPMapName(
						Net::AFP::MapParms::kUTF8NameToUserUUID, $utf8name,
						\$uuid);
				if ($rc == Net::AFP::Result::kFPItemNotFound) {
					$rc = $afpSession->FPMapName(
							Net::AFP::MapParms::kUTF8NameToGroupUUID, $utf8name,
							\$uuid);
				}
			}
			# if we can't map a name to a UUID, then just tell the client
			# that we can't proceed.
			return -&EINVAL if $rc != Net::AFP::Result::kFPNoErr;

			$$entry{'ace_applicable'} = $uuid;
			$$entry{'ace_flags'} = shift(@acl_parts);
			$$entry{'ace_rights'} = shift(@acl_parts);
			push(@entries, $entry);
		}
		my $acl = {
					'acl_ace'	=> [ @entries ],
					'acl_flags'	=> $acl_flags,
				  };
		# send the ACL on to the AFP server.
		$rc = $afpSession->FPSetACL($currVolID, $topDirID,
				Net::AFP::ACL::kFileSec_ACL, $pathType, $fileName, $acl);
		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	# handle comment xattr {{{2
	elsif ($attr eq COMMENT_XATTR && defined $DTRefNum) {
		# If either of the flags is present, apply extra checking for the
		# presence of a finder comment.
		if ($flags) {
			my $comment;
			my $rc = $afpSession->FPGetComment($DTRefNum, $topDirID,
					$pathType, $fileName, \$comment);
			if ($flags & XATTR_CREATE) {
				return -&EEXIST
						if $rc == Net::AFP::Result::kFPItemNotFound;
			} elsif ($flags & XATTR_REPLACE) {
				return -&ENODATA
						unless $rc == Net::AFP::Result::kFPItemNotFound;
			}
		}
		my $rc = $afpSession->FPAddComment($DTRefNum, $topDirID, $pathType,
				$fileName, $value);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP
				unless $volAttrs & Net::AFP::VolAttrs::kSupportsExtAttrs;

		if (defined $client_uuid) {
			my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
					$client_uuid,
					Net::AFP::ACL::KAUTH_VNODE_WRITE_EXTATTRIBUTES,
					$pathType, $fileName);
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
			return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		}

		# Set flags to pass to the server for special handling of the
		# extended attribute.
		my $xaflags = Net::AFP::ExtAttrs::kXAttrNoFollow;
		if ($flags & XATTR_CREATE) {
			$xaflags |= Net::AFP::ExtAttrs::kXAttrCreate;
		}
		if ($flags & XATTR_REPLACE) {
			$xaflags |= Net::AFP::ExtAttrs::kXAttrReplace;
		}
		# Send the set request to the server.
		my $rc = $afpSession->FPSetExtAttr($currVolID, $topDirID, $xaflags, 0,
				$pathType, $fileName, $attr, $value);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		# hopefully this is correct...
		if ($rc == Net::AFP::Result::kFPMiscErr) {
			return -&EEXIST  if $flags & XATTR_CREATE;
			return -&ENODATA if $flags & XATTR_REPLACE;
		}
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	return -&EOPNOTSUPP;
} # }}}1

sub afp_getxattr { # {{{1
	my($file, $attr) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR &&
			defined($client_uuid)) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
				$client_uuid, Net::AFP::ACL::KAUTH_VNODE_READ_SECURITY,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

		# get the ACL from the server.
		my $resp;
		$rc = $afpSession->FPGetACL($currVolID, $topDirID,
				Net::AFP::ACL::kFileSec_ACL, 0, $pathType, $fileName, \$resp);
		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		# Check to see if the server actually sent us an ACL in its
		# response; if the file has no ACL, it'll just not return one.
		if ($$resp{'Bitmap'} & Net::AFP::ACL::kFileSec_ACL) {
			my @acl_parts;
			foreach my $entry (@{$$resp{'acl_ace'}}) {
				my $name;
				# map the UUID (this actually works for both user and group
				# UUIDs, the FPMapID docs are useless) to a corresponding
				# user or group name.
				my $rc = $afpSession->FPMapID(
						Net::AFP::MapParms::kUserUUIDToUTF8Name,
						$$entry{'ace_applicable'}, \$name);
				return -&EBADF if $rc != Net::AFP::Result::kFPNoErr;
				push(@acl_parts, pack('LS/aLL', $$name{'Bitmap'},
						encode_utf8($$name{'UTF8Name'}),
						@$entry{'ace_flags', 'ace_rights'}));
			}
			# Pack the ACL into a single byte sequence, and push it to
			# the client.
			return pack('LS/(a*)', $$resp{'acl_flags'}, @acl_parts);
		}
	} # }}}2
	# handle comment xattr {{{2
	elsif ($attr eq COMMENT_XATTR && defined $DTRefNum) {
		# If the desktop DB was opened, then try getting the finder comment
		# for the file. If one is present, return it.
		my $comment;
		$rc = $afpSession->FPGetComment($DTRefNum, $topDirID, $pathType,
				$fileName, \$comment);
		if ($rc == Net::AFP::Result::kFPNoErr && defined($comment)) {
			return $comment;
		}
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP
				unless $volAttrs & Net::AFP::VolAttrs::kSupportsExtAttrs;

		if (defined $client_uuid) {
			my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
					$client_uuid,
					Net::AFP::ACL::KAUTH_VNODE_READ_EXTATTRIBUTES,
					$pathType, $fileName);
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
			return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		}

		my $resp;
		my $rc = $afpSession->FPGetExtAttr($currVolID, $topDirID,
				Net::AFP::ExtAttrs::kXAttrNoFollow, 0, -1, 131072, $pathType,
				$fileName, $attr, \$resp);
		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		# hopefully this is correct...
		return -&ENODATA if $rc == Net::AFP::Result::kFPMiscErr;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		if (defined $resp->{'AttributeData'} &&
				$resp->{'AttributeData'} ne '') {
			return $resp->{'AttributeData'};
		}
	} # }}}2
	return -&ENODATA;
} # }}}1

sub afp_listxattr { # {{{1
	my($file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	return -&EOPNOTSUPP
			unless $volAttrs & Net::AFP::VolAttrs::kSupportsExtAttrs;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my @attrs;
	my $resp;

	# general xattr handling {{{2
	if ($volAttrs & Net::AFP::VolAttrs::kSupportsExtAttrs) {
		if (defined $client_uuid) {
			my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
					$client_uuid,
					Net::AFP::ACL::KAUTH_VNODE_READ_EXTATTRIBUTES,
					$pathType, $fileName);
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
			return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		}

		# Ask the server what extended attributes it knows for the file.
		my $rc = $afpSession->FPListExtAttrs($currVolID, $topDirID,
				Net::AFP::ExtAttrs::kXAttrNoFollow, 0, 0, 131072, $pathType,
				$fileName, \$resp);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		@attrs = map { 'user.' . $_ } @{$resp->{'AttributeNames'}};
	} # }}}2

	undef $resp;
	# Try getting the ACL for the indicated file; if there's an ACL
	# present, then include the special name in the list of extended
	# attributes.
	# handle ACL xattr {{{2
	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
				$client_uuid, Net::AFP::ACL::KAUTH_VNODE_READ_SECURITY,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

		$rc = $afpSession->FPGetACL($currVolID, $topDirID,
				Net::AFP::ACL::kFileSec_ACL, 0, $pathType, $fileName, \$resp);
		if ($rc == Net::AFP::Result::kFPNoErr &&
				($$resp{'Bitmap'} & Net::AFP::ACL::kFileSec_ACL)) {
			push(@attrs, ACL_XATTR);
		}
	} # }}}2
	# If the desktop DB was opened (should have been...), check for a
	# finder comment on the file.
	# handle comment xattr {{{2
	if (defined $DTRefNum) {
		my $comment;
		$rc = $afpSession->FPGetComment($DTRefNum, $topDirID, $pathType,
				$fileName, \$comment);
		if ($rc == Net::AFP::Result::kFPNoErr && defined($comment)) {
			push(@attrs, COMMENT_XATTR);
		}
	} # }}}2
	return(@attrs, 0);
} # }}}1

sub afp_removexattr { # {{{1
	my($file, $attr) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR &&
			defined($client_uuid)) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
				$client_uuid, Net::AFP::ACL::KAUTH_VNODE_WRITE_SECURITY,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;

		# Remove the ACL from the indicated file.
		$rc = $afpSession->FPSetACL($currVolID, $topDirID,
				Net::AFP::ACL::kFileSec_REMOVEACL, $pathType, $fileName);

		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	# handle comment xattr {{{2
	elsif ($attr eq COMMENT_XATTR && defined $DTRefNum) {
		# Remove the finder comment, if one is present.
		my $rc = $afpSession->FPRemoveComment($DTRefNum, $topDirID,
				$pathType, $fileName);
		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENODATA if $rc == Net::AFP::Result::kFPItemNotFound;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP
				unless $volAttrs & Net::AFP::VolAttrs::kSupportsExtAttrs;
		if (defined $client_uuid) {
			my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0,
					$client_uuid,
					Net::AFP::ACL::KAUTH_VNODE_WRITE_EXTATTRIBUTES,
					$pathType, $fileName);
			return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
			return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
			return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
		}

		# Remove the requested extended attribute from the indicated file.
		my $rc = $afpSession->FPRemoveExtAttr($currVolID, $topDirID,
				Net::AFP::ExtAttrs::kXAttrNoFollow, $pathType, $fileName,
				$attr);
		return -&EACCES  if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT  if $rc == Net::AFP::Result::kFPObjectNotFound;
		# hopefully this is correct...
		return -&ENODATA if $rc == Net::AFP::Result::kFPMiscErr;
		return -&EBADF   if $rc != Net::AFP::Result::kFPNoErr;
		return 0;
	} # }}}2
	return -&ENODATA;
} # }}}1

sub lookup_afp_entry { # {{{1
	my ($fileName, $deleteEntry) = @_;

	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	my $resp = undef;

	if (defined $client_uuid) {
		my $rc = $afpSession->FPAccess($currVolID, $topDirID, 0, $client_uuid,
				Net::AFP::ACL::KAUTH_VNODE_READ_ATTRIBUTES,
				$pathType, $fileName);
		return -&EACCES if $rc == Net::AFP::Result::kFPAccessDenied;
		return -&ENOENT if $rc == Net::AFP::Result::kFPObjectNotFound;
		return -&EBADF  if $rc != Net::AFP::Result::kFPNoErr;
	}

	my $fileBitmap = Net::AFP::FileParms::kFPCreateDateBit |
					 Net::AFP::FileParms::kFPModDateBit |
					 Net::AFP::FileParms::kFPNodeIDBit |
					 Net::AFP::FileParms::kFPParentDirIDBit |
					 $DForkLenFlag;
	my $dirBitmap = Net::AFP::DirParms::kFPCreateDateBit |
					Net::AFP::DirParms::kFPModDateBit |
					Net::AFP::DirParms::kFPNodeIDBit |
					Net::AFP::DirParms::kFPOffspringCountBit |
					Net::AFP::DirParms::kFPParentDirIDBit;
	if ($volAttrs & Net::AFP::VolAttrs::kSupportsUnixPrivs) {
		$fileBitmap |= Net::AFP::FileParms::kFPUnixPrivsBit;
		$dirBitmap |= Net::AFP::DirParms::kFPUnixPrivsBit;
	}

	my $rc = $afpSession->FPGetFileDirParms($currVolID, $topDirID,
			$fileBitmap, $dirBitmap, $pathType, $fileName, \$resp);

	return($rc, $resp)	if $rc == Net::AFP::Result::kFPNoErr;
	return -&EACCES		if $rc == Net::AFP::Result::kFPAccessDenied;
	return -&ENOENT		if $rc == Net::AFP::Result::kFPObjectNotFound;
	return -&EINVAL		if $rc == Net::AFP::Result::kFPParamErr;
	return -&EBADF;

} # }}}1

sub translate_path { # {{{1
	my ($path) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	
	my @pathparts = split(/\//, $path);
	my @afp_path = ();
	foreach my $elem (@pathparts) {
		next if $elem eq '.';
		next if $elem eq '';
		if ($elem eq '..') {
			next if scalar(@afp_path) <= 0;
			pop(@afp_path);
			next;
		}
		$elem =~ tr/:/\//;
		push(@afp_path, $elem);
	}
	return join("\0", @afp_path);
} # }}}1

sub node_name { # {{{1
	my ($xlatedPath) = @_;

	my @path_parts = split(/\0/, $xlatedPath);
	return pop(@path_parts);
} # }}}1

sub path_parent { # {{{1
	my ($xlatedPath) = @_;

	my @path_parts = split(/\0/, $xlatedPath);
	pop(@path_parts);
	return join("\0", @path_parts);
} # }}}1

# vim: ts=4 fdm=marker sw=4 et
