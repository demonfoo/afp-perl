package Net::AFP::Fuse;

use base qw(Fuse::Class);

# imports {{{1
# Enables a nice call trace on warning events.
use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

use strict;
use warnings;
no warnings qw(redefine);
use diagnostics;

use Net::AFP::TCP;				# the class which actually sets up and
								# handles the guts of talking to an AFP
								# server via TCP/IP
use Net::AFP::Atalk;			# The class to connect to an AppleTalk server
								# via AppleTalk protocol.
use Net::AFP::Result;			# AFP result codes
use Net::AFP::VolAttrs;			# volume attribute definitions
use Net::AFP::VolParms;			# parameters for FPOpenVol()
use Net::AFP::UAMs;				# User Auth Method helper code
use Net::AFP::Versions;			# version checking/agreement helper code
use Net::AFP::MapParms;			# mapping function operation codes
use Net::AFP::FileParms qw(:DEFAULT !:common);
use Net::AFP::DirParms;
use Net::AFP::ExtAttrs;
use Net::AFP::ACL;
use Net::Atalk::NBP;
use Encode;						# handle encoding/decoding strings
use Socket;						# for socket related constants for
								# parent/child IPC code
use Fcntl qw(:mode);			# macros and constants related to symlink
								# checking code
use Data::Dumper;				# for diagnostic output when debugging is on
use Errno qw(:POSIX);	# Standard errors codes.
# File opening mode macros.
use Fcntl qw(O_RDONLY O_WRONLY O_RDWR O_ACCMODE);
use Fuse qw(:xattr);

sub ENODATA { return($^O eq 'freebsd' ? &Errno::ENOATTR : &Errno::ENODATA); }

# We need Data::UUID for a portable means to get a UUID to identify
# ourselves to the AFP server for FPAccess() calls; if it's there, it's
# definitely preferred.
my $has_Data_UUID = 1;
eval { require Data::UUID; };
if ($@) { $has_Data_UUID = 0; }

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

# Set up the pattern to use for breaking the AFP URL into its components.
my $url_rx = qr|^
                  (afps?):/             # protocol specific prefix
                  (at)?/                # optionally specify atalk transport
                  (?:                   # authentication info block
                      ([^:\@\/;]*)      # capture username
                      (?:;AUTH=([^:\@\/;]+))? # capture uam name
                      (?::([^:\@\/;]*))? # capture password
                  \@)?                  # closure of auth info capture
                  (?\|([^:\/\@\[\]:]+)\|\[([^\]]+)\]) # capture target host
                  (?::([^:\/\@;]+))?    # capture optional port
                  (?:\/(?:              # start path capture
                      ([^:\/\@;]+)      # first path element is vol name
                      (\/.*)?           # rest of path is local subpath
                  )?)?                  # closure of path capture
                  $|x;
my @args = ('protocol', 'atalk_transport', 'username', 'UAM', 'password',
		'host', 'port', 'volume', 'subpath');

sub new { # {{{1
	my ($class, $url, $pw_cb) = @_;
	
	my $obj = $class->SUPER::new();
	$$obj{'topDirID'} = 2;
	$$obj{'volID'} = undef;
	$$obj{'DTRefNum'} = undef;
	$$obj{'afpconn'} = undef;
	# open fork numbers for files that have been opened via afp_open()
	$$obj{'ofcache'} = {};

	my %urlparms;
	@urlparms{@args} = $url =~ $url_rx;
	die('Unable to extract host from AFP URL')
			unless defined $urlparms{'host'};
	die('Unable to extract volume from AFP URL')
			unless defined $urlparms{'volume'};
	foreach (keys(%urlparms)) { $urlparms{$_} = urldecode($urlparms{$_}); }

	# Use FPGetSrvrInfo() to get some initial information about the server for
	# use later in the connection process.
	# get server information {{{2
	my $srvInfo;
	my $rc;
	if ($urlparms{'atalk_transport'}) {
		# Query for one record that will match, and return as soon as we
		# have it.
		my @records = NBPLookup($urlparms{'host'}, 'AFPServer',
				$urlparms{'port'}, undef, 1);
		die("Could not resolve NBP name " . $urlparms{'host'})
				unless scalar(@records);
		@urlparms{'hostaddr', 'sockno'} = @{$records[0]}[0,1];
	
		$rc = Net::AFP::Atalk->GetStatus(@urlparms{'hostaddr', 'sockno'},
				\$srvInfo);
	}
	else {
		$rc = Net::AFP::TCP->GetStatus(@urlparms{'host', 'port'}, \$srvInfo);
	}
	if ($rc != kFPNoErr) {
		print "Could not issue GetStatus on ", $urlparms{'host'}, "\n";
		return ENODEV;
	}
	# }}}2

	# Actually open a session to the server.
	# open server connection {{{2
	if ($urlparms{'atalk_transport'}) {
		$$obj{'afpconn'} = new Net::AFP::Atalk(@urlparms{'hostaddr', 'sockno'});
	}
	else {
		$$obj{'afpconn'} = new Net::AFP::TCP(@urlparms{'host', 'port'});
	}
	unless (ref($$obj{'afpconn'}) ne '' and
			$$obj{'afpconn'}->isa('Net::AFP')) {
		print "Could not connect via AFP to ", $urlparms{'host'}, "\n";
		return ENODEV;
	}
	# }}}2

	# Establish which AFP protocol version the server has in common with us.
	# Abort if (by chance) we can't come to an agreement.
	# version agreement {{{2
	my $commonVersion = Net::AFP::Versions::GetPreferredVersion(
			$$srvInfo{'AFPVersions'}, $urlparms{'atalk_transport'});
	if (!defined $commonVersion) {
		print "Couldn't agree on an AFP protocol version with the server\n";
		$obj->disconnect();
		return ENODEV;
	}
	# }}}2

	# Authenticate with the server.
	# do authentication {{{2
	if (defined $urlparms{'username'}) {
		my $uamList = $$srvInfo{'UAMs'};
		if (defined $urlparms{'UAM'}) {
			$uamList = [ $urlparms{'UAM'} ];
		}
		my $rc = Net::AFP::UAMs::PasswordAuth($$obj{'afpconn'}, $commonVersion,
				$uamList, $urlparms{'username'}, sub { return &$pw_cb(@urlparms{'username', 'host', 'password'}); });
		unless ($rc == kFPNoErr) {
			print "Incorrect username/password while trying to authenticate\n";
			$obj->disconnect();
			return EACCES;
		}
	} else {
		# do anonymous auth to the AFP server instead
		my $rc = Net::AFP::UAMs::GuestAuth($$obj{'afpconn'}, $commonVersion);
		unless ($rc == kFPNoErr) {
			print "Anonymous authentication to server failed (maybe no ",
					"guest auth allowed?)\n";
			$obj->disconnect();
			return EACCES;
		}
	} # }}}2

	# Since AFP presents pre-localized times for everything, we need to get
	# the server's time offset, and compute the difference between that and
	# our timestamp, to appropriately apply time localization.
	my $srvParms;
	$rc = $$obj{'afpconn'}->FPGetSrvrParms(\$srvParms);
	if ($rc != kFPNoErr) {
		$obj->disconnect();
		return EACCES;
	}
	$$obj{'timedelta'} = time() - $$srvParms{'ServerTime'};
	
	# Open the volume indicated at start time, and abort if the server bitches
	# at us.
	# open volume {{{2
	my $volInfo;
	$rc = $$obj{'afpconn'}->FPOpenVol(kFPVolAttributeBit |
			kFPVolSignatureBit, $urlparms{'volume'}, undef,
			\$volInfo);
	if ($rc == kFPAccessDenied) {
		# no volume password; does apple's AFP server even support volume
		# passwords anymore? I don't really know.
		print "Server expected volume password\n";
		$obj->disconnect();
		return EACCES;
	} elsif ($rc == kFPObjectNotFound || $rc == kFPParamErr) {
		# Server didn't know the volume we asked for.
		print 'Volume "', $urlparms{'volume'}, "\" does not exist on server\n";
		$obj->disconnect();
		return ENODEV;
	} elsif ($rc != kFPNoErr) {
		# Some other error occurred; if the docs are to be believed, this should
		# never happen unless we pass bad flags (coding error) or some
		# non-AFP-specific condition causes a failure (which is out of our
		# hands)...
		print 'FPOpenVol failed with error ', $rc, ' (',
				strerror($rc), ")\n";
		$obj->disconnect();
		return ENODEV;
	}
	print Dumper($volInfo) if defined $::_DEBUG;
	
	if ($$volInfo{'Signature'} == 3) {
		print "Volume uses variable Directory IDs; not currently supported\n";
		$obj->disconnect();
		return EINVAL;
	}
	
	$$obj{'volID'} = $$volInfo{'ID'};
	# Copy out the attribute value, since there are some flags we should really
	# be checking in there (you know, for UTF8 support, extended attributes,
	# ACLs, things like that)...
	$$obj{'volAttrs'} = $$volInfo{'VolAttribute'};

	$$obj{'pathType'}	= kFPLongName; # AFP long names by default
	$$obj{'pathFlag'}	= kFPLongNameBit;
	$$obj{'pathkey'}	= 'LongName';

	if ($$obj{'volAttrs'} & kSupportsUTF8Names) {
		# If the remote volume does UTF8 names, then we'll go with that..
		$$obj{'pathType'}	= kFPUTF8Name;
		$$obj{'pathFlag'}	= kFPUTF8NameBit;
		$$obj{'pathkey'}	= 'UTF8Name';
	}

	$$obj{'DForkLenFlag'}	= kFPDataForkLenBit;
	$$obj{'RForkLenFlag'}	= kFPRsrcForkLenBit;
	$$obj{'DForkLenKey'}	= 'DataForkLen';
	$$obj{'RForkLenKey'}	= 'RsrcForkLen';
	$$obj{'UseExtOps'}		= 0;
	# I *think* large file support entered the picture as of AFP 3.0...
	if (Net::AFP::Versions::CompareByVersionNum($$obj{'afpconn'}, 3, 0,
			kFPVerAtLeast)) {
		$$obj{'DForkLenFlag'}	= kFPExtDataForkLenBit;
		$$obj{'RForkLenFlag'}	= kFPExtRsrcForkLenBit;
		$$obj{'DForkLenKey'}	= 'ExtDataForkLen';
		$$obj{'RForkLenKey'}	= 'ExtRsrcForkLen';
		$$obj{'UseExtOps'}		= 1;
	}

	# Not checking the return code here. If this fails, $$self{'DTRefNum'} won't be
	# defined, so we don't need to worry about possible later unpredictable
	# failures due to this.
	$$obj{'afpconn'}->FPOpenDT($$obj{'volID'}, \$$obj{'DTRefNum'});

	if ($$obj{'volAttrs'} & kSupportsACLs) {
	    if ($has_Data_UUID) {
		    my $uo = new Data::UUID;
		    $$obj{'client_uuid'} = $uo->create();
	    } else {
		    print "Need Data::UUID class for full ACL functionality, ACL checking disabled\n";
    	}
	}
	# }}}2

	# If a subpath is defined, find the node ID for the directory, and use that
	# as the root; if the node isn't found or is not a directory, then abort.
	# lookup node ID for subpath mount {{{2
	if (defined $urlparms{'subpath'}) {
		print 'Looking up directory \'', $urlparms{'subpath'},
				"' as pivot point for root node\n" if defined $::_DEBUG;
		my $realDirPath = translate_path($urlparms{'subpath'});
		my $dirBitmap = kFPNodeIDBit;

		my $resp;
		my $rc = $$obj{'afpconn'}->FPGetFileDirParms($$obj{'volID'},
				$$obj{'topDirID'}, $dirBitmap, $dirBitmap, $$obj{'pathType'},
				$realDirPath, \$resp);
	
		if ($rc != kFPNoErr || !exists $$resp{'NodeID'}) {
			print STDERR "ERROR: Specified directory not found\n";
			$obj->disconnect();
			return ENODEV;
		}

		if ($$resp{'FileIsDir'} != 1) {
			print STDERR "ERROR: Attempted to pivot mount root to non-directory\n";
			$obj->disconnect();
			return ENOTDIR;
		}
		$$obj{'topDirID'} = $$resp{'NodeID'};
		print "Mount root node ID changed to ", $$obj{'topDirID'}, "\n"
				if defined $::_DEBUG;
	} # }}}2

	# purify URL # {{{2
	my $scrubbed_url = $urlparms{'protocol'} . '://';
	if (defined $urlparms{'username'}) {
		$scrubbed_url .= urlencode($urlparms{'username'}) . '@';
	}
	if ($urlparms{'host'} =~ /:/) {
		$scrubbed_url .= '[' . $urlparms{'host'} . ']';
	}
	else {
		$scrubbed_url .= urlencode($urlparms{'host'});
	}
	if (defined $urlparms{'port'}) {
		$scrubbed_url .= ':' . $urlparms{'port'};
	}
	$scrubbed_url .= '/';
	if (defined $urlparms{'volume'}) {
		$scrubbed_url .= urlencode($urlparms{'volume'});
		if (defined $urlparms{'subpath'}) {
			$scrubbed_url .= urlencode($urlparms{'subpath'});
		}
	}
	$_[1] = $scrubbed_url;
	# }}}2

	return $obj;
} # }}}1

sub disconnect { # {{{1
	my ($self) = @_;

	if (defined $$self{'afpconn'}) {
		$$self{'afpconn'}->FPCloseDT($$self{'DTRefNum'})
				if defined $$self{'DTRefNum'};
		$$self{'afpconn'}->FPCloseVol($$self{'volID'})
				if defined $$self{'volID'};
		$$self{'afpconn'}->FPLogout();
		$$self{'afpconn'}->close();
	}
} # }}}1

sub getattr { # {{{1
	my ($self, $file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my ($rc, $resp) = $self->lookup_afp_entry($fileName);
	return $rc if $rc != kFPNoErr;

	return -&ENOENT if $$resp{'NodeID'} == 0;

	# assemble stat record {{{2
	my @stat = (
		# device number (just make it 0, since it's not a real device)
		0,
		# inode number (node ID works fine)
		$$resp{'NodeID'},
		# permission mask
		exists($$resp{'UnixPerms'}) ? $$resp{'UnixPerms'} :
				($$resp{'FileIsDir'} ? 040755 : 0100644),
		# link count; not really technically correct (should just be the
        # number of subdirs), but there's not a convenient way to get just
        # that via AFP, other than walking the directory. for what it's
        # worth, it looks (empirically) like this is what apple's client
        # does too, instead of walking the dir.
		$$resp{'FileIsDir'} ? $$resp{'OffspringCount'} + 2 : 1,
		# UID number
		exists($$resp{'UnixUID'}) ? $$resp{'UnixUID'} : 0,
		# GID number
		exists($$resp{'UnixGID'}) ? $$resp{'UnixGID'} : 0,
		# device special major/minor number
		0,
		# file size in bytes
		$$resp{'FileIsDir'} ? 4096 : $$resp{$$self{'DForkLenKey'}},
		# last accessed time
		$$resp{'ModDate'} + $$self{'timedelta'},
		# data modified time
		$$resp{'ModDate'} + $$self{'timedelta'},
		# inode changed time
		$$resp{'CreateDate'} + $$self{'timedelta'},
		# preferred block size
		512,
		# size in blocks
		$$resp{'FileIsDir'} ? 1 : int(($$resp{$$self{'DForkLenKey'}} - 1) / 512) + 1
	);
	# }}}2
	return(@stat);
} # }}}1

sub readlink { # {{{1
	my ($self, $file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	# Classic MacOS' concept of an "alias", so far as I can tell, doesn't
	# really translate to the UNIX concept of a symlink; I might be able
	# to implement it later via file IDs, but until then, if UNIX permissions
	# aren't present, this won't work.
	return -&EINVAL unless $$self{'volAttrs'} & kSupportsUnixPrivs;

	$file = decode(ENCODING, $file);
	# Break the provided path down into a directory ID and filename.
	my $fileName = translate_path($file);

	# Get the UNIX privilege info for the file.
	my $fileBitmap = kFPUnixPrivsBit;
	my $resp;
	my $rc = $$self{'afpconn'}->FPGetFileDirParms($$self{'volID'}, $$self{'topDirID'},
			$fileBitmap, 0, $$self{'pathType'}, $fileName, \$resp);
	return -&EACCES if $rc == kFPAccessDenied;
	return -&ENOENT if $rc == kFPObjectNotFound;
	return -&EBADF  if $rc != kFPNoErr;

	# The UNIX privilege info is pretty universal, so just use the standard
	# macros to see if the permissions show it to be a symlink.
	# process symlink {{{2
	if (S_ISLNK($$resp{'UnixPerms'})) {
		# Now we have to open the "data fork" of this pseudo-file, read the
		# "contents" (a single line containing the path of the symbolic link),
		# and return that.
		my $sresp;
		$rc = $$self{'afpconn'}->FPOpenFork(0, $$self{'volID'}, $$self{'topDirID'}, 0, 0x1,
				$$self{'pathType'}, $fileName, \$sresp);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EINVAL if $rc == kFPParamErr;
		return -&EMFILE if $rc == kFPTooManyFilesOpen;
		return -&EBADF  if $rc != kFPNoErr;
		
		my $linkPath;
		my $pos = 0;
		do {
			my $readText;
			if ($$self{'UseExtOps'}) {
				$rc = $$self{'afpconn'}->FPReadExt($$sresp{'OForkRefNum'}, $pos,
						1024, \$readText);
			} else {
				$rc = $$self{'afpconn'}->FPRead($$sresp{'OForkRefNum'}, $pos,
						1024, undef, undef, \$readText);
			}
			return -&EACCES if $rc == kFPAccessDenied;
			return -&EINVAL unless $rc == kFPNoErr or $rc == kFPEOFErr;
			$linkPath .= $readText;
		} until ($rc == kFPEOFErr);
		$$self{'afpconn'}->FPCloseFork($$sresp{'OForkRefNum'});
		return encode(ENCODING, $linkPath);
	} # }}}2

	return -&EINVAL;
} # }}}1

sub getdir { # {{{1
	my ($self, $dirname) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$dirname = decode(ENCODING, $dirname);
	my $fileName = translate_path($dirname);
	my @filesList = ('.', '..');

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_LIST_DIRECTORY, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	my $resp;
	# Set the result set size limit; if there are more entries in the
	# directory, extra requests will have to be sent. Larger set sizes
	# mean less time spent waiting around for responses.
	my $setsize = 500;
	my @arglist = ($$self{'volID'}, $$self{'topDirID'}, $$self{'pathFlag'}, $$self{'pathFlag'}, $setsize, 1,
			32767, $$self{'pathType'}, $fileName, \$resp);
	my $rc = undef;
	# loop reading entries {{{2
	while (1) {
		$rc = $$self{'afpconn'}->FPEnumerateExt2(@arglist);
		if ($rc == kFPCallNotSupported) {
			$rc = $$self{'afpconn'}->FPEnumerateExt(@arglist);
			if ($rc == kFPCallNotSupported) {
				$rc = $$self{'afpconn'}->FPEnumerate(@arglist);
			}
		}

		last unless $rc == kFPNoErr;

		# Under some circumstances (no, this is not an error elsewhere in
		# my code, near as I can tell) on a second swipe, we'll get *one*
		# dirent back, which is a file we already got. that means that's
		# the end.
		if ($arglist[5] > 1 &&
				($$resp[0]{$$self{'pathkey'}} eq $filesList[$#filesList])) {
			shift(@$resp);
			$arglist[5]++;
		}
		# anyone actually trying to readdir() gets the entries in reverse
		# order, for some odd reason; bug in FUSE driver/libfuse/Fuse module?
		push(@filesList, map {
						my $name = $$_{$$self{'pathkey'}};
						$name =~ tr/\//:/;
						encode(ENCODING, $name); } @$resp);

		# Set up for a subsequent call to get directory entries.
		$arglist[5] += scalar(@$resp);
		undef $resp;
	}
	# }}}2
	if ($rc == kFPObjectNotFound or $rc == kFPNoErr) {
		return(reverse(@filesList), 0);
	}
	return -&EACCES  if $rc == kFPAccessDenied;
	return -&ENOENT  if $rc == kFPDirNotFound;
	return -&ENOTDIR if $rc == kFPObjectTypeErr;
	return -&EINVAL  if $rc == kFPParamErr;
	return -&EACCES;
}
# }}}1

sub mknod { # {{{1
	my ($self, $file, $mode, $devnum) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	if (S_ISREG($mode)) {
		my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
		return $rc if $rc != kFPNoErr;
		if (defined $$self{'client_uuid'}) {
			my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
					$$self{'client_uuid'}, KAUTH_VNODE_ADD_FILE,
					$$self{'pathType'}, path_parent($fileName));
			return -&EACCES if $rc == kFPAccessDenied;
			return -&ENOENT if $rc == kFPObjectNotFound;
			return -&EBADF  if $rc != kFPNoErr;
		}

		$rc = $$self{'afpconn'}->FPCreateFile(0, $$self{'volID'}, $$resp{'NodeID'},
				 $$self{'pathType'}, node_name($fileName));
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOSPC if $rc == kFPDiskFull;
		return -&EBUSY  if $rc == kFPFileBusy;
		return -&EEXIST if $rc == kFPObjectExists;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EINVAL if $rc == kFPParamErr;
		return -&EROFS  if $rc == kFPVolLocked;
		return -&EBADF  if $rc != kFPNoErr;
		return 0;
	}
	return -&EOPNOTSUPP;
} # }}}1

sub mkdir { # {{{1
	my ($self, $file, $mode) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my $newDirID;
	my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
	return $rc if $rc != kFPNoErr;
	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_ADD_SUBDIRECTORY, $$self{'pathType'},
				path_parent($fileName));
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	$rc = $$self{'afpconn'}->FPCreateDir($$self{'volID'}, $$resp{'NodeID'}, $$self{'pathType'},
			node_name($fileName), \$newDirID);
	return 0		if $rc == kFPNoErr;
	return -&EPERM	if $rc == kFPAccessDenied;
	return -&ENOSPC	if $rc == kFPDiskFull;
	return -&EPERM	if $rc == kFPFlatVol;
	return -&ENOENT	if $rc == kFPObjectNotFound;
	return -&EEXIST	if $rc == kFPObjectExists;
	return -&EINVAL	if $rc == kFPParamErr;
	return -&EROFS	if $rc == kFPVolLocked;
	return -&EBADF;
} # }}}1

sub unlink { # {{{1
	my ($self, $file) = @_;

	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my ($rc, $resp) = $self->lookup_afp_entry(path_parent($fileName));
	return $rc if $rc != kFPNoErr;

	if (exists $$self{'ofcache'}{$fileName}) {
		$$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
		delete $$self{'ofcache'}{$fileName};
	}

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_DELETE, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	# don't have to worry about checking to ensure we're 'rm'ing a file;
	# this works for both, verifying that "unlink" is being invoked on a
	# non-directory is done elsewhere. also, we're referencing this sub
	# as the implementation for rmdir as well, which should work just fine
	# since the same backend call does both.
	$rc = $$self{'afpconn'}->FPDelete($$self{'volID'}, $$resp{'NodeID'}, $$self{'pathType'},
			node_name($fileName));
	return 0			if $rc == kFPNoErr;
	return -&EACCES		if $rc == kFPAccessDenied;
	return -&EBUSY		if $rc == kFPFileBusy;
	return -&EBUSY		if $rc == kFPObjectLocked;
	return -&ENOENT		if $rc == kFPObjectNotFound;
	return -&EISDIR		if $rc == kFPObjectTypeErr;
	return -&EINVAL		if $rc == kFPParamErr;
	return -&EROFS		if $rc == kFPVolLocked;
	return -&ENOTEMPTY	if $rc == kFPDirNotEmpty;
	return -&EBADF;
} # }}}1

sub rmdir { return Net::AFP::Fuse::unlink(@_); }

# seems OS X 10.4 causes the newly created symlink to be locked, so once
# you create it, you can't remove it via AFP until you unmount the volume
# once. good work apple. :| doesn't happen on netatalk or OS X 10.5.
sub symlink { # {{{1
	my ($self, $target, $linkname) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	return -&EPERM unless $$self{'volAttrs'} & kSupportsUnixPrivs;

	$linkname = decode(ENCODING, $linkname);
	my $fileName = translate_path($linkname);

	# FIXME: add FPAccess() check
	
	# create the target file first
	# create target file {{{2
	my $rc = $$self{'afpconn'}->FPCreateFile(0, $$self{'volID'}, $$self{'topDirID'}, $$self{'pathType'},
			$fileName);
	return -&EACCES if $rc == kFPAccessDenied;
	return -&ENOSPC if $rc == kFPDiskFull;
	return -&EBUSY  if $rc == kFPFileBusy;
	return -&EEXIST if $rc == kFPObjectExists;
	return -&ENOENT if $rc == kFPObjectNotFound;
	return -&EINVAL if $rc == kFPParamErr;
	return -&EROFS  if $rc == kFPVolLocked;
	return -&EBADF  if $rc != kFPNoErr;
	# }}}2

	# open the file, and write out the path given as the link target...
	# open and write link target {{{2
	my $resp;
	$rc = $$self{'afpconn'}->FPOpenFork(0, $$self{'volID'}, $$self{'topDirID'}, 0, 0x3,
			$$self{'pathType'}, $fileName, \$resp);
	return -&EACCES  if $rc == kFPAccessDenied;
	return -&ETXTBSY if $rc == kFPDenyConflict;
	return -&ENOENT  if $rc == kFPObjectNotFound;
	return -&EACCES  if $rc == kFPObjectLocked;
	return -&EISDIR  if $rc == kFPObjectTypeErr;
	return -&EINVAL  if $rc == kFPParamErr;
	return -&EMFILE  if $rc == kFPTooManyFilesOpen;
	return -&EROFS   if $rc == kFPVolLocked;
	return -&EBADF   if $rc != kFPNoErr;
	my $forkID = $$resp{'OForkRefNum'};

	my $lastWritten;
	if ($$self{'UseExtOps'}) {
		$rc = $$self{'afpconn'}->FPWriteExt(0, $forkID, 0, length($target),
				\$target, \$lastWritten);
	} else {
		$rc = $$self{'afpconn'}->FPWrite(0, $forkID, 0, length($target),
				\$target, \$lastWritten);
	}

	$$self{'afpconn'}->FPCloseFork($forkID);

	return -&EACCES  if $rc == kFPAccessDenied;
	return -&ENOSPC  if $rc == kFPDiskFull;
	return -&ETXTBSY if $rc == kFPLockErr;
	return -&EINVAL  if $rc == kFPParamErr;
	return -&EBADF   if $rc != kFPNoErr;
	# }}}2

	# set finder info {{{2
	my $bitmap = kFPFinderInfoBit | kFPModDateBit;

	# apparently this is the magic to transmute a file into a symlink...
	$rc = $$self{'afpconn'}->FPSetFileParms($$self{'volID'}, $$self{'topDirID'}, $bitmap,
			$$self{'pathType'}, $fileName, 'FinderInfo' => 'slnkrhap',
			'ModDate' => time() + $$self{'timedelta'});
	
	return 0		if $rc == kFPNoErr;
	return -&EACCES if $rc == kFPAccessDenied;
	return -&ENOENT if $rc == kFPObjectNotFound;
	return -&EINVAL if $rc == kFPParamErr;
	return -&EBADF;
	# }}}2

} # }}}1

sub rename { # {{{1
	my ($self, $oldName, $newName) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

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
	
	my ($rc, $old_stat) = $self->lookup_afp_entry($oldXlated, 1);
	return $rc if $rc != kFPNoErr;
	my $new_stat;
	($rc, $new_stat) = $self->lookup_afp_entry($newXlated);
	return $rc if $rc != kFPNoErr;

	# FIXME: add FPAccess() check

	my @arglist;
	my $resp;
	if ($$old_stat{'FileIsDir'} == 1) {
		@arglist = ($$self{'volID'}, $$old_stat{'ParentDirID'},
				$$new_stat{'NodeID'}, $$self{'pathType'}, $oldRealName,
				$$self{'pathType'}, '', $$self{'pathType'}, $newRealName, \$resp);
	} else {
		@arglist = ($$self{'volID'}, $$old_stat{'ParentDirID'},
				$$new_stat{'NodeID'}, $$self{'pathType'}, $oldRealName, $$self{'pathType'}, '',
				$$self{'pathType'}, $newRealName, \$resp);
	}
	$rc = $$self{'afpconn'}->FPMoveAndRename(@arglist);

	if ($rc == kFPObjectExists) {
		$$self{'afpconn'}->FPDelete($$self{'volID'}, $$new_stat{'NodeID'}, $$self{'pathType'},
				$newRealName);
		$rc = $$self{'afpconn'}->FPMoveAndRename(@arglist);
	}
	if ($rc == kFPNoErr) {
        # Move the open filehandle for the renamed file to the new name,
        # if there is one.
        if (exists $$self{'ofcache'}{$oldXlated}) {
            $$self{'ofcache'}{$newXlated} = $$self{'ofcache'}{$oldXlated};
            delete $$self{'ofcache'}{$oldXlated};
        }
        return 0;
    }
	return -&EACCES	if $rc == kFPAccessDenied;
	return -&EINVAL	if $rc == kFPCantMove;
	return -&EBUSY	if $rc == kFPObjectLocked;
	return -&ENOENT	if $rc == kFPObjectNotFound;
	return -&EINVAL	if $rc == kFPParamErr;
	return -&EROFS	if $rc == kFPVolLocked;
	return -&EBADF;
} # }}}1

sub link { # {{{1
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	return -&EOPNOTSUPP;
} # }}}1

sub chmod { # {{{1
	my ($self, $file, $mode) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	
	my $fileName = translate_path(decode(ENCODING, $file));
	my ($rc, $resp) = $self->lookup_afp_entry($fileName, 1);
	return $rc if $rc != kFPNoErr;

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_WRITE_ATTRIBUTES, $$self{'pathType'},
				$fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	$rc = $$self{'afpconn'}->FPSetFileDirParms($$self{'volID'}, $$self{'topDirID'},
			kFPUnixPrivsBit, $$self{'pathType'}, $fileName,
			'UnixPerms'			=> $mode | S_IFMT($$resp{'UnixPerms'}),
			'UnixUID'			=> $$resp{'UnixUID'},
			'UnixGID'			=> $$resp{'UnixGID'},
			'UnixAccessRights'	=> $$resp{'UnixAccessRights'});
	return -&EPERM  if $rc == kFPAccessDenied;
	return -&ENOENT if $rc == kFPObjectNotFound;
	return -&EINVAL if $rc == kFPParamErr;
	return -&EROFS  if $rc == kFPVolLocked;
	return -&EBADF  if $rc != kFPNoErr;

	return 0;
} # }}}1

sub chown { # {{{1
	my ($self, $file, $uid, $gid) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	my $fileName = translate_path(decode(ENCODING, $file));
	my ($rc, $resp) = $self->lookup_afp_entry($fileName, 1);
	return $rc if $rc != kFPNoErr;

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_CHANGE_OWNER, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	$rc = $$self{'afpconn'}->FPSetFileDirParms($$self{'volID'}, $$self{'topDirID'},
			kFPUnixPrivsBit, $$self{'pathType'}, $fileName,
			'UnixPerms'			=> $$resp{'UnixPerms'},
			'UnixUID'			=> $uid,
			'UnixGID'			=> $gid,
			'UnixAccessRights'	=> $$resp{'UnixAccessRights'});
	return -&EPERM  if $rc == kFPAccessDenied;
	return -&ENOENT if $rc == kFPObjectNotFound;
	return -&EINVAL if $rc == kFPParamErr;
	return -&EROFS  if $rc == kFPVolLocked;
	return -&EBADF  if $rc != kFPNoErr;

	return 0;
} # }}}1

sub truncate { # {{{1
	my ($self, $file, $length) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	my $ofork;
	my $close_fork = 0;

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_WRITE_DATA, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	my $rc;
	if (exists $$self{'ofcache'}{$fileName}) {
		$ofork = $$self{'ofcache'}{$fileName}{'refnum'};
	} else {
		my $resp;
		$rc = $$self{'afpconn'}->FPOpenFork(0, $$self{'volID'}, $$self{'topDirID'}, 0, 0x3,
				$$self{'pathType'}, $fileName, \$resp);
		return -&EPERM  if $rc == kFPAccessDenied;
		return -&EPERM  if $rc == kFPDenyConflict;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EPERM  if $rc == kFPObjectLocked;
		return -&EISDIR if $rc == kFPObjectTypeErr;
		return -&EINVAL if $rc == kFPParamErr;
		return -&EMFILE if $rc == kFPTooManyFilesOpen;
		return -&EROFS  if $rc == kFPVolLocked;
		return -&EBADF  if $rc != kFPNoErr;

		$ofork = $$resp{'OForkRefNum'};
		$close_fork = 1;
	}

	$rc = $$self{'afpconn'}->FPSetForkParms($ofork, $$self{'DForkLenFlag'}, $length);

	$$self{'afpconn'}->FPCloseFork($ofork) if $close_fork == 1;

	return 0		if $rc == kFPNoErr;
	return -&EPERM  if $rc == kFPAccessDenied;
	return -&ENOSPC if $rc == kFPDiskFull;
	return -&EPERM  if $rc == kFPLockErr;
	return -&EINVAL if $rc == kFPParamErr;
	return -&EROFS  if $rc == kFPVolLocked;
	return -&EBADF;
} # }}}1

sub utime { # {{{1
	my ($self, $file, $actime, $modtime) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my $rc = $$self{'afpconn'}->FPSetFileDirParms($$self{'volID'}, $$self{'topDirID'},
			kFPCreateDateBit | kFPModDateBit, $$self{'pathType'}, $fileName,
			'CreateDate' => $actime - $$self{'timedelta'},
			'ModDate' => $modtime - $$self{'timedelta'});
	return 0		if $rc == kFPNoErr;
	return -&EPERM	if $rc == kFPAccessDenied;
	return -&ENOENT	if $rc == kFPObjectNotFound;
	return -&EINVAL	if $rc == kFPParamErr;
	return -&EROFS	if $rc == kFPVolLocked;
	return -&EBADF;
} # }}}1

sub open { # {{{1
	my ($self, $file, $mode) = @_;
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
        # HACK: Thanks Apple. Way to, I don't know, know how to IMPLEMENT
        # YOUR OWN PROTOCOL. Seems if you open the file write-only, and
        # then, oh, try to WRITE TO IT, the writes then fail. Wow. That
        # makes so much sense!
		$accessBitmap = 0x3;
	} elsif (($mode & O_ACCMODE) == O_RDONLY) {
		$accessBitmap = 0x1;
	}

	# Speaking of being lied to, fuse claims release() doesn't get called
	# until the last reference goes away. Um... not so much really. It
	# happily closes and reopens filehandles mid-stream. This really
	# breaks the model. Fortunately a little refcounting fixes it
	# right up...
	if (exists $$self{'ofcache'}{$fileName}) {
		my $cachedBitmap = $$self{'ofcache'}{$fileName}{'mode'};
		if (($cachedBitmap & $accessBitmap) == $cachedBitmap) {
			$$self{'ofcache'}{$fileName}{'refcount'}++;
			return 0;
		}
		$self->flush($file_u);
		$refcount = $$self{'ofcache'}{$fileName}{'refcount'};
		my $rc = $$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
		delete $$self{'ofcache'}{$fileName};
		$accessBitmap = 0x3;
	}

	my $resp;
	my $rc = $$self{'afpconn'}->FPOpenFork(0, $$self{'volID'}, $$self{'topDirID'}, 0,
			$accessBitmap, $$self{'pathType'}, $fileName, \$resp);
	if ($rc == kFPNoErr) {
		$$self{'ofcache'}{$fileName} = {
				'ostamp'			=> time(),
				'astamp'			=> time(),
				'mode'				=> $accessBitmap,
				'refnum'			=> $$resp{'OForkRefNum'},
				'coalesce_offset'	=> undef,
				'coalesce_len'		=> undef,
				'coalesce_buf'		=> "\0" x COALESCE_MAX,
				'refcount'			=> $refcount + 1 };
		return(0);
	}
	return -&EACCES  if $rc == kFPAccessDenied;
	return -&ETXTBSY if $rc == kFPDenyConflict;
	return -&ENOENT  if $rc == kFPObjectNotFound;
	return -&EACCES  if $rc == kFPObjectLocked;
	return -&EISDIR  if $rc == kFPObjectTypeErr;
	return -&EINVAL  if $rc == kFPParamErr;
	return -&EMFILE  if $rc == kFPTooManyFilesOpen;
	return -&EROFS   if $rc == kFPVolLocked;
	return -&EBADF;
} # }}}1

sub read { # {{{1
	my ($self, $file, $len, $off) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$self->fsync($file);

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	return -&EBADF unless exists $$self{'ofcache'}{$fileName};

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_READ_DATA, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	my $forkID = $$self{'ofcache'}{$fileName}{'refnum'};
	$$self{'ofcache'}{$fileName}{'astamp'} = time();
	my $resp;
	my $rc;
	if ($$self{'UseExtOps'}) {
		$rc = $$self{'afpconn'}->FPReadExt($forkID, $off, $len, \$resp);
	} else {
		$rc = $$self{'afpconn'}->FPRead($forkID, $off, $len, undef, undef, \$resp);
	}
	return $resp     if (($rc == kFPNoErr)
			|| ($rc == kFPEOFErr && defined($resp)));
	return -&ESPIPE  if $rc == kFPEOFErr;
	return -&EBADF   if $rc == kFPAccessDenied;
	return -&ETXTBSY if $rc == kFPLockErr;
	return -&EINVAL  if $rc == kFPParamErr;
	return -&EBADF;
} # }}}1

sub write { # {{{1
	#my ($file, $data, $offset) = @_;
    my ($self, $file, $offset) = @_[0,1,3];
    my $data_r = \$_[2];
	print 'called ', (caller(0))[3], "('", $file, "', [data], ", $offset, ")\n"
			if defined $::_DEBUG;

	my $file_u = $file;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	return -&EBADF unless exists $$self{'ofcache'}{$fileName};

	my $of_ent = $$self{'ofcache'}{$fileName};
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
		my $rv = $self->flush($file_u);
		if ($rv != 0) {
			return $rv;
		}
	}

	# FIXME: add FPAccess() check

    my $dlen = length($$data_r);
	if (defined $$of_ent{'coalesce_offset'}) {
		if ($offset == ($$of_ent{'coalesce_offset'} +
				$$of_ent{'coalesce_len'})) {
			substr($$of_ent{'coalesce_buf'}, $$of_ent{'coalesce_len'},
                    $dlen, $$data_r);
			$$of_ent{'coalesce_len'} += $dlen;
			return $dlen;
		} else {
			my $rv = $self->flush($file_u);
			if ($rv != 0) {
				return $rv;
			}
		}
	} else {
		substr($$of_ent{'coalesce_buf'}, 0, $dlen, $$data_r);
		$$of_ent{'coalesce_len'} = $dlen;
		$$of_ent{'coalesce_offset'} = $offset;
		return length($$data_r);
	}
	# }}}2
	my $lastWritten;
	my $rc;
	if ($$self{'UseExtOps'}) {
		$rc = $$self{'afpconn'}->FPWriteExt(0, $forkID, $offset, $dlen,
				$data_r, \$lastWritten);
	} else {
		$rc = $$self{'afpconn'}->FPWrite(0, $forkID, $offset, $dlen,
                $data_r, \$lastWritten);
	}
	
	return($lastWritten - $offset) if $rc == kFPNoErr;
	return -&EACCES		 if $rc == kFPAccessDenied;
	return -&ENOSPC		 if $rc == kFPDiskFull;
	return -&ETXTBSY	 if $rc == kFPLockErr;
	return -&EINVAL		 if $rc == kFPParamErr;
	return -&EBADF		 if $rc != kFPNoErr;
} # }}}1

sub statfs { # {{{1
	my ($self) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;
	my $VolBitmap;
	my $bf_key;
	my $bt_key;
	my $blocksize = 512;
	if ($$self{'UseExtOps'}) {
		$VolBitmap |= kFPVolExtBytesFreeBit | kFPVolExtBytesTotalBit |
					  kFPVolBlockSizeBit;
		$bf_key = 'ExtBytesFree';
		$bt_key = 'ExtBytesTotal';
	} else {
		$VolBitmap |= kFPVolBytesFreeBit | kFPVolBytesTotalBit;
		$bf_key = 'BytesFree';
		$bt_key = 'BytesTotal';
	}
	my $resp;
	my $rc = $$self{'afpconn'}->FPGetVolParms($$self{'volID'}, $VolBitmap, \$resp);
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

sub flush { # {{{1
	my ($self, $file) = @_;
	print 'called ', (caller(0))[3], "('", $file, "')\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	if (exists $$self{'ofcache'}{$fileName}) {
		# This is the second (and critical) part of write coalescing -
		# flushing the writes out to the remote volume. I'm probably
		# implementing this in a rather naive fashion, but it works so
		# far...
		if (defined $$self{'ofcache'}{$fileName}{'coalesce_offset'}) {
			my($forkID, $offset, $len) =
					@{$$self{'ofcache'}{$fileName}}{'refnum', 'coalesce_offset',
											  'coalesce_len'};
            my $data_ref = \$$self{'ofcache'}{$fileName}{'coalesce_buf'};
#			if ($$self{'ofcache'}{$fileName}{'coalesce_len'} < COALESCE_MAX) {
#				my $data = substr($$data_ref, 0, $$self{'ofcache'}{$fileName}{'coalesce_len'});
#				$data_ref = \$data;
#			}
			my $lastwr;
			my $rc;
			my $write_fn = \&Net::AFP::FPWrite;
			if ($$self{'UseExtOps'}) { $write_fn = \&Net::AFP::FPWriteExt }

			# Try to zero-copy whenever possible...
			$rc = &$write_fn($$self{'afpconn'}, 0, $forkID, $offset, $len,
					$data_ref, \$lastwr);
			# Continue writing if needed.
			while ($lastwr < ($offset + $len) && $rc == kFPNoErr) {
				my $dchunk = substr($$data_ref, $lastwr - $offset,
						$offset + $len - $lastwr);
				$rc = &$write_fn($$self{'afpconn'}, 0, $forkID, $lastwr,
						length($dchunk), \$dchunk, \$lastwr);
			}
			undef $$self{'ofcache'}{$fileName}{'coalesce_offset'};
		}
	}

	return(0);
} # }}}1

sub release { # {{{1
	my ($self, $file, $mode) = @_;
	print 'called ', (caller(0))[3], "('", $file, "', ", $mode, ")\n"
			if defined $::_DEBUG;

	my $file_u = $file;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	if (exists $$self{'ofcache'}{$fileName}) {
		# If the reference count is not 0, just play along.
		return(0) if --$$self{'ofcache'}{$fileName}{'refcount'};
		$self->flush($file_u);
		$$self{'afpconn'}->FPCloseFork($$self{'ofcache'}{$fileName}{'refnum'});
		delete $$self{'ofcache'}{$fileName};
		return 0;
	}
	return -&EBADF;
} # }}}1

sub fsync { # {{{1
	my ($self, $file, $flags) = @_;
	print 'called ', (caller(0))[3], "('", $file, "')\n"
			if defined $::_DEBUG;

	return $self->flush($file);
} # }}}1

sub setxattr { # {{{1
	my ($self, $file, $attr, $value, $flags) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	$value = decode(ENCODING, $value);

	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR && defined($$self{'client_uuid'})) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_WRITE_SECURITY, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;

		# if either of the flags is present, apply extra checking for the
		# presence of an ACL.
		if ($flags) {
			my $resp;
			$rc = $$self{'afpconn'}->FPGetACL($$self{'volID'}, $$self{'topDirID'},
					kFileSec_ACL, 0, $$self{'pathType'}, $fileName, \$resp);
			if ($flags & XATTR_CREATE) {
				return -&EEXIST if $$resp{'Bitmap'} & kFileSec_ACL;
			} elsif ($flags & XATTR_REPLACE) {
				return -&ENODATA unless $$resp{'Bitmap'} & kFileSec_ACL;
			}
		}
	
		my $acl;
		my $rv = $self->acl_from_xattr($value, \$acl);
		if ($rv != 0) {
			return $rv;
		}
		# send the ACL on to the AFP server.
		$rc = $$self{'afpconn'}->FPSetACL($$self{'volID'}, $$self{'topDirID'}, kFileSec_ACL,
				$$self{'pathType'}, $fileName, $acl);
		return -&EACCES  if $rc == kFPAccessDenied;
		return -&ENOENT  if $rc == kFPObjectNotFound;
		return -&EBADF   if $rc != kFPNoErr;
		return 0;
	} # }}}2
	# handle comment xattr {{{2
	# comment stuff is deprecated as of AFP 3.3...
	elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
		# If either of the flags is present, apply extra checking for the
		# presence of a finder comment.
		if ($flags) {
			my $comment;
			my $rc = $$self{'afpconn'}->FPGetComment($$self{'DTRefNum'}, $$self{'topDirID'},
					$$self{'pathType'}, $fileName, \$comment);
			if ($flags & XATTR_CREATE) {
				return -&EEXIST
						if $rc == kFPItemNotFound;
			} elsif ($flags & XATTR_REPLACE) {
				return -&ENODATA
						unless $rc == kFPItemNotFound;
			}
		}
		my $rc = $$self{'afpconn'}->FPAddComment($$self{'DTRefNum'}, $$self{'topDirID'}, $$self{'pathType'},
				$fileName, $value);
		return -&EACCES     if $rc == kFPAccessDenied;
		return -&ENOENT     if $rc == kFPObjectNotFound;
        return -&EOPNOTSUPP if $rc == kFPCallNotSupported;
		return -&EBADF      if $rc != kFPNoErr;
		return 0;
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;

		if (defined $$self{'client_uuid'}) {
			my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
					$$self{'client_uuid'}, KAUTH_VNODE_WRITE_EXTATTRIBUTES, $$self{'pathType'},
					$fileName);
			return -&EACCES if $rc == kFPAccessDenied;
			return -&ENOENT if $rc == kFPObjectNotFound;
			return -&EBADF  if $rc != kFPNoErr;
		}

		# Set flags to pass to the server for special handling of the
		# extended attribute.
		my $xaflags = kXAttrNoFollow;
		if ($flags & XATTR_CREATE) {
			$xaflags |= kXAttrCreate;
		}
		if ($flags & XATTR_REPLACE) {
			$xaflags |= kXAttrReplace;
		}
		# Send the set request to the server.
		my $rc = $$self{'afpconn'}->FPSetExtAttr($$self{'volID'}, $$self{'topDirID'},
				$xaflags, 0, $$self{'pathType'}, $fileName, $attr, $value);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		# hopefully this is correct...
		if ($rc == kFPMiscErr) {
			return -&EEXIST  if $flags & XATTR_CREATE;
			return -&ENODATA if $flags & XATTR_REPLACE;
		}
		return -&EBADF  if $rc != kFPNoErr;
		return 0;
	} # }}}2
	return -&EOPNOTSUPP;
} # }}}1

sub getxattr { # {{{1
	my ($self, $file, $attr) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR &&
			defined($$self{'client_uuid'})) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_READ_SECURITY, $$self{'pathType'}, $fileName);
		return -&ENODATA if $rc == kFPAccessDenied;
		return -&ENODATA if $rc == kFPObjectNotFound;
		return -&EBADF   if $rc != kFPNoErr;

		# get the ACL from the server.
		my $resp;
		$rc = $$self{'afpconn'}->FPGetACL($$self{'volID'}, $$self{'topDirID'}, kFileSec_ACL,
				0, $$self{'pathType'}, $fileName, \$resp);
		return -&ENODATA if $rc == kFPAccessDenied;
		return -&ENODATA if $rc == kFPObjectNotFound;
		return -&EBADF   if $rc != kFPNoErr;
		# Check to see if the server actually sent us an ACL in its
		# response; if the file has no ACL, it'll just not return one.
		if ($$resp{'Bitmap'} & kFileSec_ACL) {
			return $self->acl_to_xattr($resp);
		}
	} # }}}2
	# handle comment xattr {{{2
	# comment stuff is deprecated as of AFP 3.3...
	elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
		# If the desktop DB was opened, then try getting the finder comment
		# for the file. If one is present, return it.
		my $comment;
		my $rc = $$self{'afpconn'}->FPGetComment($$self{'DTRefNum'}, $$self{'topDirID'}, $$self{'pathType'},
				$fileName, \$comment);
		if ($rc == kFPNoErr && defined($comment)) {
			return $comment;
		}
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;

		if (defined $$self{'client_uuid'}) {
			my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
					$$self{'client_uuid'}, KAUTH_VNODE_READ_EXTATTRIBUTES, $$self{'pathType'},
					$fileName);
			return -&ENODATA if $rc == kFPAccessDenied;
			return -&ENODATA if $rc == kFPObjectNotFound;
			return -&EBADF   if $rc != kFPNoErr;
		}

		my $resp;
		my $rc = $$self{'afpconn'}->FPGetExtAttr($$self{'volID'}, $$self{'topDirID'},
				kXAttrNoFollow, 0, -1, 131072, $$self{'pathType'}, $fileName, $attr,
				\$resp);
		return -&ENODATA if $rc == kFPAccessDenied;
		return -&ENODATA if $rc == kFPObjectNotFound;
		# hopefully this is correct...
		return -&ENODATA if $rc == kFPMiscErr;
		return -&EBADF   if $rc != kFPNoErr;
		if (defined $$resp{'AttributeData'} &&
				$$resp{'AttributeData'} ne '') {
			return $$resp{'AttributeData'};
		}
	} # }}}2
	return -&EOPNOTSUPP;
} # }}}1

sub listxattr { # {{{1
	my ($self, $file) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;
	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);

	my @attrs;
	my $resp;

	# general xattr handling {{{2
	if ($$self{'volAttrs'} & kSupportsExtAttrs) {
		if (defined $$self{'client_uuid'}) {
			my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
					$$self{'client_uuid'}, KAUTH_VNODE_READ_EXTATTRIBUTES, $$self{'pathType'},
					$fileName);
			return -&EACCES if $rc == kFPAccessDenied;
			return -&ENOENT if $rc == kFPObjectNotFound;
			return -&EBADF  if $rc != kFPNoErr;
		}

		# Ask the server what extended attributes it knows for the file.
		my $rc = $$self{'afpconn'}->FPListExtAttrs($$self{'volID'}, $$self{'topDirID'},
				kXAttrNoFollow, 0, 0, 131072, $$self{'pathType'}, $fileName, \$resp);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
		@attrs = map { 'user.' . $_ } @{$$resp{'AttributeNames'}};
	} # }}}2

	undef $resp;
	# Try getting the ACL for the indicated file; if there's an ACL
	# present, then include the special name in the list of extended
	# attributes.
	# handle ACL xattr {{{2
	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_READ_SECURITY, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;

		$rc = $$self{'afpconn'}->FPGetACL($$self{'volID'}, $$self{'topDirID'}, kFileSec_ACL, 0,
				$$self{'pathType'}, $fileName, \$resp);
		if ($rc == kFPNoErr && ($$resp{'Bitmap'} & kFileSec_ACL)) {
			push(@attrs, ACL_XATTR);
		}
	} # }}}2
	# If the desktop DB was opened (should have been...), check for a
	# finder comment on the file.
	# handle comment xattr {{{2
	# comment stuff is deprecated as of AFP 3.3...
	if (defined $$self{'DTRefNum'}) {
		my $comment;
		my $rc = $$self{'afpconn'}->FPGetComment($$self{'DTRefNum'}, $$self{'topDirID'}, $$self{'pathType'},
				$fileName, \$comment);
		if ($rc == kFPNoErr && defined($comment)) {
			push(@attrs, COMMENT_XATTR);
		}
	} # }}}2
	return(@attrs, 0);
} # }}}1

sub removexattr { # {{{1
	my ($self, $file, $attr) = @_;
	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	$file = decode(ENCODING, $file);
	my $fileName = translate_path($file);
	$attr = decode(ENCODING, $attr);
	# handle ACL xattr {{{2
	if ($attr eq ACL_XATTR &&
			defined($$self{'client_uuid'})) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_WRITE_SECURITY, $$self{'pathType'}, $fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;

		# Remove the ACL from the indicated file.
		$rc = $$self{'afpconn'}->FPSetACL($$self{'volID'}, $$self{'topDirID'},
				kFileSec_REMOVEACL, $$self{'pathType'}, $fileName);

		return -&EACCES  if $rc == kFPAccessDenied;
		return -&ENOENT  if $rc == kFPObjectNotFound;
		return -&EBADF   if $rc != kFPNoErr;
		return 0;
	} # }}}2
	# handle comment xattr {{{2
	# comment stuff is deprecated as of AFP 3.3...
	elsif ($attr eq COMMENT_XATTR && defined $$self{'DTRefNum'}) {
		# Remove the finder comment, if one is present.
		my $rc = $$self{'afpconn'}->FPRemoveComment($$self{'DTRefNum'}, $$self{'topDirID'},
				$$self{'pathType'}, $fileName);
		return -&EACCES  if $rc == kFPAccessDenied;
		return -&ENODATA if $rc == kFPItemNotFound;
		return -&ENOENT  if $rc == kFPObjectNotFound;
		return -&EBADF   if $rc != kFPNoErr;
		return 0;
	} # }}}2
	# general xattr handling {{{2
	elsif ($attr =~ /^user\./) {
		$attr =~ s/^user\.//;

		return -&EOPNOTSUPP unless $$self{'volAttrs'} & kSupportsExtAttrs;
		if (defined $$self{'client_uuid'}) {
			my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
					$$self{'client_uuid'}, KAUTH_VNODE_WRITE_EXTATTRIBUTES, $$self{'pathType'},
					$fileName);
			return -&EACCES if $rc == kFPAccessDenied;
			return -&ENOENT if $rc == kFPObjectNotFound;
			return -&EBADF  if $rc != kFPNoErr;
		}

		# Remove the requested extended attribute from the indicated file.
		my $rc = $$self{'afpconn'}->FPRemoveExtAttr($$self{'volID'},
				$$self{'topDirID'}, kXAttrNoFollow, $$self{'pathType'},
				$fileName, $attr);
		return -&EACCES  if $rc == kFPAccessDenied;
		return -&ENOENT  if $rc == kFPObjectNotFound;
		# hopefully this is correct...
		return -&ENODATA if $rc == kFPMiscErr;
		return -&EBADF   if $rc != kFPNoErr;
		return 0;
	} # }}}2
	return -&ENODATA;
} # }}}1


# misc. helper functions below:

sub lookup_afp_entry { # {{{1
	my ($self, $fileName, $deleteEntry) = @_;

	print 'called ', (caller(0))[3], "(", join(', ', @_), ")\n"
			if defined $::_DEBUG;

	my $resp = undef;

	if (defined $$self{'client_uuid'}) {
		my $rc = $$self{'afpconn'}->FPAccess($$self{'volID'}, $$self{'topDirID'}, 0,
				$$self{'client_uuid'}, KAUTH_VNODE_READ_ATTRIBUTES, $$self{'pathType'},
				$fileName);
		return -&EACCES if $rc == kFPAccessDenied;
		return -&ENOENT if $rc == kFPObjectNotFound;
		return -&EBADF  if $rc != kFPNoErr;
	}

	my $fileBitmap = kFPCreateDateBit | kFPModDateBit | kFPNodeIDBit |
					 kFPParentDirIDBit | $$self{'DForkLenFlag'};
	my $dirBitmap = kFPCreateDateBit | kFPModDateBit | kFPNodeIDBit |
					kFPOffspringCountBit | kFPParentDirIDBit;
	if ($$self{'volAttrs'} & kSupportsUnixPrivs) {
		$fileBitmap |= kFPUnixPrivsBit;
		$dirBitmap |= kFPUnixPrivsBit;
	}

	my $rc = $$self{'afpconn'}->FPGetFileDirParms($$self{'volID'}, $$self{'topDirID'},
			$fileBitmap, $dirBitmap, $$self{'pathType'}, $fileName, \$resp);

	return($rc, $resp)	if $rc == kFPNoErr;
	return -&EACCES		if $rc == kFPAccessDenied;
	return -&ENOENT		if $rc == kFPObjectNotFound;
	return -&EINVAL		if $rc == kFPParamErr;
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

# Helper function to convert a byte-string form ACL from the ACL update client
# into the structured form to be sent to the server.
sub acl_from_xattr { # {{{1
	my ($self, $raw_xattr, $acl_data) = @_;

	# unpack the ACL from the client, so we can structure it to be handed
	# up to the AFP server
	my($acl_flags, @acl_parts) = unpack('NS/(LS/aLL)', $raw_xattr);
	my @entries;
	while (scalar(@acl_parts) > 0) {
		my $entry = {};
		my $bitmap = shift(@acl_parts);
		my $utf8name = decode_utf8(shift(@acl_parts));
		my($uuid, $rc);
		# do the appropriate type of name lookup based on the attributes
		# given in the bitmap field.
		if ($bitmap == kFileSec_UUID) {
			$rc = $$self{'afpconn'}->FPMapName(kUTF8NameToUserUUID, $utf8name,
					\$uuid);
		} elsif ($bitmap == kFileSec_GRPUUID) {
			$rc = $$self{'afpconn'}->FPMapName(kUTF8NameToGroupUUID, $utf8name,
					\$uuid);
		} else {
			$rc = $$self{'afpconn'}->FPMapName(kUTF8NameToUserUUID, $utf8name,
					\$uuid);
			if ($rc == kFPItemNotFound) {
				$rc = $$self{'afpconn'}->FPMapName(kUTF8NameToGroupUUID,
						$utf8name, \$uuid);
			}
		}
		# if we can't map a name to a UUID, then just tell the client
		# that we can't proceed.
		return -&EINVAL if $rc != kFPNoErr;

		$$entry{'ace_applicable'} = $uuid;
		$$entry{'ace_flags'} = shift(@acl_parts);
		$$entry{'ace_rights'} = shift(@acl_parts);
		push(@entries, $entry);
	}
	$$acl_data = {
				'acl_ace'	=> [ @entries ],
				'acl_flags'	=> $acl_flags,
			  };
	return 0;
} # }}}1

# Helper function to convert an AFP ACL into a format that is consumable
# by afp_acl.pl (the tool for manipulating ACLs on an AFP share).
sub acl_to_xattr { # {{{1
	my ($self, $acldata) = @_;

	my @acl_parts;
	foreach my $entry (@{$$acldata{'acl_ace'}}) {
		my $name;
		# map the UUID (this actually works for both user and group
		# UUIDs, the FPMapID docs are useless) to a corresponding
		# user or group name.
		my $rc = $$self{'afpconn'}->FPMapID(kUserUUIDToUTF8Name,
				$$entry{'ace_applicable'}, \$name);
		return -&EBADF if $rc != kFPNoErr;
		push(@acl_parts, pack('LS/aLL', $$name{'Bitmap'},
				encode_utf8($$name{'UTF8Name'}),
				@$entry{'ace_flags', 'ace_rights'}));
	}
	# Pack the ACL into a single byte sequence, and push it to
	# the client.
	return pack('LS/(a*)', $$acldata{'acl_flags'}, @acl_parts);
} # }}}1

sub urldecode { # {{{1
	my ($string) = @_;
	if (defined $string) {
		$string =~ tr/+/ /;
		$string =~ s/\%([0-9a-f]{2})/chr(hex($1))/gei;
	}
	return $string;
} # }}}1

sub urlencode { # {{{1
	my ($string) = @_;
	if (defined $string) {
		$string =~ s/([^\w\/_\-. ])/sprintf('%%%02x',ord($1))/gei;
		$string =~ tr/ /+/;
	}
	return $string;
} # }}}1

1;
# vim: ts=4 fdm=marker sw=4 et