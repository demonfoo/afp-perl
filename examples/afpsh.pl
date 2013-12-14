#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

# Pull in all the AFP packages that we need, for the connection object
# itself and return code symbols, helper functions for version handling
# and UAMs, etc.
use Net::AFP::Helpers;
use Net::AFP;
use Net::AFP::Result;
use Net::AFP::VolParms;
use Net::AFP::VolAttrs;
use Net::AFP::UAMs;
use Net::AFP::ACL;
use Net::AFP::MapParms;
use Net::AFP::Versions;
use Net::AFP::FileParms qw(:DEFAULT !:common);
use Net::AFP::DirParms;
use Socket;

use Term::ReadLine;     # for reading input from user

use IO::File;
use Text::ParseWords;   # for "shell" style command parsing
use Getopt::Long qw(GetOptionsFromArray);
                        # for command-line option parsing
use Data::Dumper;       # for debugging; remove later
use POSIX;              # for POSIX time handling
use File::Basename;
use Term::ReadPassword;
use Time::HiRes qw(gettimeofday);
use Text::Glob qw(match_glob);
use Encode;
use I18N::Langinfo qw(langinfo CODESET);
use Cwd();

# Find out the character encoding for the current terminal.
my $term_enc = langinfo(CODESET);

my $has_Data__UUID = 0;
eval { require Data::UUID; 1; } and do { $has_Data__UUID = 1; };

my $has_Archive__Tar = 1;
eval { require Archive::Tar; 1; } or do {
    print "Sorry, Archive::Tar not available.\n";
    $has_Archive__Tar = 0;
};

my %UUID_cache = ();

# Turn on some debugging for the AFP and DSI layers. Can produce a _lot_ of
# output - use with care.
our $__AFP_DEBUG;
our $__DSI_DEBUG;

my %afpopts;
my($atalk_first, $prefer_v4);
Getopt::Long::Configure('no_ignore_case');
GetOptions( 'debug-afp' => sub { $__AFP_DEBUG = 1; },
            'debug-dsi' => sub { $__DSI_DEBUG = 1; },
            'atalk-first' => \$atalk_first,
            'prefer-v4' => \$prefer_v4);

$afpopts{aforder} = [AF_INET];
if ($prefer_v4) {
    push(@{$afpopts{aforder}}, AF_INET6);
} else {
    unshift(@{$afpopts{aforder}}, AF_INET6);
}
if ($atalk_first) {
    unshift(@{$afpopts{aforder}}, AF_APPLETALK);
} else {
    push(@{$afpopts{aforder}}, AF_APPLETALK);
}

my($path) = @ARGV;

my $pw_cb = sub {
    my(%values) = @_;
    my $prompt = 'Password: ';
    return $values{password} if defined $values{password};
    return read_password($prompt);
};
my($session, %values) = do_afp_connect($pw_cb, $path || q{}, undef, %afpopts);
unless (ref($session) && $session->isa('Net::AFP')) {
    exit($session);
}

# If no volume was named, contact the server and find out the volumes
# it knows, and spit those out in a friendly format.
unless ($values{volume}) {
    my $srvrParms;
    $session->FPGetSrvrParms(\$srvrParms);
    print <<'_EOT_';

Volume Name                                 | UNIX privs? | Volume pass?
-------------------------------------------------------------------------
_EOT_
    foreach my $volume (@{$$srvrParms{Volumes}}) {
        printf("\%-43s |     \%-3s     |     \%s\n", $volume->{VolName},
                $volume->{HasUNIXPrivs} ? 'Yes' : 'No',
                $volume->{HasPassword} ? 'Yes' : 'No');
    }

    $session->FPLogout();
    $session->close();
    exit(0);
}

my $volInfo;
my $rc = $session->FPOpenVol(kFPVolAttributeBit, $values{volume}, undef,
        \$volInfo);
unless ($rc == kFPNoErr) {
    print "Volume was unknown?\n";
    $session->FPLogout();
    $session->close();
    exit(1);
}

my $volID = $$volInfo{ID};
my $DT_ID;
$rc = $session->FPOpenDT($volID, \$DT_ID);
unless ($rc == kFPNoErr) {
    print "Couldn't open Desktop DB\n";
    undef $DT_ID;
#   $session->FPCloseVol($volID);
#   $session->FPLogout();
#   $session->close();
}

my $volAttrs = $volInfo->{VolAttribute};

my $client_uuid;
if ($volAttrs & kSupportsACLs) {
    if ($has_Data__UUID) {
        my $uo = new Data::UUID;
        $client_uuid = $uo->create();
    }
    else {
        print "Need Data::UUID class for full ACL functionality, ACL checking disabled\n";
    }
}

my $pathType    = kFPLongName;
my $pathFlag    = kFPLongNameBit;
my $pathkey     = 'LongName';

if ($volAttrs & kSupportsUTF8Names) {
    # If the remote volume does UTF8 names, then we'll go with that..
    $pathType       = kFPUTF8Name;
    $pathFlag       = kFPUTF8NameBit;
    $pathkey        = 'UTF8Name';
}

my $topDirID = 2;
my $term = new Term::ReadLine 'afpsh';
my $curdirnode = $topDirID;

my $DForkLenFlag    = kFPDataForkLenBit;
my $RForkLenFlag    = kFPRsrcForkLenBit;
my $DForkLenKey     = 'DataForkLen';
my $RForkLenKey     = 'RsrcForkLen';
my $EnumFn          = \&Net::AFP::FPEnumerate;
my $ReadFn          = \&Net::AFP::FPRead;
my $WriteFn         = \&Net::AFP::FPWrite;
# I *think* large file support entered the picture as of AFP 3.0...
if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
        kFPVerAtLeast)) {
    $DForkLenFlag   = kFPExtDataForkLenBit;
    $RForkLenFlag   = kFPExtRsrcForkLenBit;
    $DForkLenKey    = 'ExtDataForkLen';
    $RForkLenKey    = 'ExtRsrcForkLen';
    $ReadFn         = \&Net::AFP::FPReadExt;
    $WriteFn        = \&Net::AFP::FPWriteExt;
    $EnumFn         = \&Net::AFP::FPEnumerateExt;
}

if (Net::AFP::Versions::CompareByVersionNum($session, 3, 1,
        kFPVerAtLeast)) {
    $EnumFn         = \&Net::AFP::FPEnumerateExt2;
}

if (defined $values{subpath}) {
    my ($newDirId, $fileName) = resolve_path($session, $volID, $curdirnode,
            $values{subpath});
    if (defined $fileName || !defined $newDirId) {
        print 'path ', $values{subpath}, ' is not accessible, defaulting ',
                "to volume root\n";
    }
    else {
        $curdirnode = $newDirId;
    }
}

my %commands = (
    ls  => sub {
        my @words = @_;
        my $fileBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
                kFPNodeIDBit | $DForkLenFlag | $RForkLenFlag |
                kFPParentDirIDBit | $pathFlag;
        if ($volInfo->{VolAttribute} & kSupportsUnixPrivs) {
            $fileBmp |= kFPUnixPrivsBit;
        }
        my $dirBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
                kFPNodeIDBit | kFPOffspringCountBit | kFPOwnerIDBit |
                kFPGroupIDBit | kFPAccessRightsBit | kFPParentDirIDBit |
                $pathFlag;
        if ($volInfo->{VolAttribute} & kSupportsUnixPrivs) {
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
            my $rc;
            my $expansion_list = expand_globbed_path($session, $volID, $curdirnode, $item);
            if (!ref($expansion_list) || scalar(@{$expansion_list}) < 1) {
                print "Sorry, couldn't find any matches for entry \"", $item, "\"\n";
                next;
            }
            if (scalar(@{$expansion_list}) > 1) {
                $printDirNames = 1;
            }
            foreach my $elem (@{$expansion_list}) {
                my @records;
                my ($dirId, $fileName, $dirName) = @{$elem};
                if (defined $fileName && $fileName ne q{}) {
                    my $resp;
                    ($rc, $resp) = $session->FPGetFileDirParms(
                            VolumeID        => $volID,
                            DirectoryID     => $dirId,
                            FileBitmap      => $fileBmp,
                            DirectoryBitmap => $dirBmp,
                            PathType        => $pathType,
                            Pathname        => $fileName);
                    push(@records, $resp) if $rc == kFPNoErr;
                }
                else {
                    my $offset = 1;
                    do {
                        $results = undef;
                        ($rc, $results) = &$EnumFn($session,
                                VolumeID        => $volID,
                                DirectoryID     => $dirId,
                                FileBitmap      => $fileBmp,
                                DirectoryBitmap => $dirBmp,
                                ReqCount        => 1024,
                                StartIndex      => $offset,
                                MaxReplySize    => 32767,
                                PathType        => $pathType,
                                Pathname        => q{});
                        if (ref($results) eq 'ARRAY') {
                            push(@records, @$results);
                            $offset += scalar(@$results);
                        }
                    } while ($rc == kFPNoErr);
                }
                if ($rc == kFPNoErr || $rc == kFPObjectNotFound) {
                    if ($printDirNames == 1 &&
                            (!defined($fileName) || $fileName eq q{})) {
                        print $dirName, ":\n";
                    }
                    do_listentries(\@records, $volID);
                    if ($printDirNames == 1 &&
                            (!defined($fileName) || $fileName eq q{})) {
                        print "\n";
                    }
                }
            }
        }
        return 1;
    },
    cat => sub {
        my @words = @_;
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);
            my($rc, %resp) = $session->FPOpenFork(
                    VolumeID    => $volID,
                    DirectoryID => $dirId,
                    AccessMode  => 0x1,
                    PathType    => $pathType,
                    Pathname    => $fileName);
            if ($rc != kFPNoErr) {
                print 'open attempt failed with code ', $rc, ' (',
                        afp_strerror($rc), ")\n";
                next;
            }
            my $pos = 0;
            while (1) {
                my $data;
                ($rc, $data) = &$ReadFn($session,
                        OForkRefNum => $resp{OForkRefNum},
                        Offset      => $pos,
                        ReqCount    => 1024);
                print $data;
                last if $rc != kFPNoErr || $data eq q{};
                $pos += length($data);
            }
            $rc = $session->FPCloseFork($resp{OForkRefNum});
            if ($rc != kFPNoErr) {
                print 'close attempt failed with code ', $rc, ' (',
                        afp_strerror($rc), ")\n";
            }
        }
        return 1;
    },
    cd  => sub {
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
        my ($newDirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                $path);
        if (defined $fileName || !defined $newDirId) {
            print "sorry, couldn't change directory\n";
            return 1;
        }
        $curdirnode = $newDirId;
        return 1;
    },
    get => sub {
        my @words = @_[1..$#_];
        my($continue, $del_src_after_get, $del_target_before_get, $basedir,
            $outputpath);
        GetOptionsFromArray(\@words,
            'c'     => \$continue,
            'E'     => \$del_src_after_get,
            'e'     => \$del_target_before_get,
            'O=s'   => \$basedir,
            'o=s'   => \$outputpath,
        );
        if (scalar(@words) < 1 or scalar(@words) > 2) {
            print <<'_EOT_';
Error: Specify the name of the file to retrieve, and optionally the name of
the file to store the local copy to. Quote the name if needed (to account
for spaces or special characters).
_EOT_
            return 1;
        }
        my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                $words[0]);
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
        my $targetFile = (scalar(@words) == 1 ? $fileName : $words[1]);
        my($rc, %resp) = $session->FPOpenFork(
                VolumeID    => $volID,
                DirectoryID => $dirId,
                AccessMode  => 0x1,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != kFPNoErr) {
            print 'open attempt failed with code ', $rc, ' (',
                    afp_strerror($rc), ")\n";
            return 1;
        }

        my $local_fh = new IO::File($targetFile, 'w');
        unless (defined $local_fh) {
            print "Couldn't open local file for writing!\n";
            $session->FPCloseFork($resp{OForkRefNum});
            return 1;
        }

        my $sresp = q{};
        my $bitmap = $DForkLenFlag | $RForkLenFlag;
        ($rc, $sresp) = $session->FPGetFileDirParms(
                VolumeID    => $volID,
                DirectoryID => $dirId,
                PathType    => $pathType,
                Pathname    => $fileName,
                FileBitmap  => $bitmap);

        if ($sresp->{$RForkLenKey} > 0) {
            print "note that the resource fork isn't handled yet!\n";
        }
        local $| = 1;
        my $pos = 0;
        my(%time, %lasttime, %starttime);
        @time{'sec', 'usec'} = gettimeofday();
        %starttime = %time;
        while (1) {
            my $data;
            ($rc, $data) = &$ReadFn($session,
                    OForkRefNum => $resp{OForkRefNum},
                    Offset      => $pos,
                    ReqCount    => 131_072);
            print $local_fh $data;
            my $rate = 0;
            my $delta = (($time{sec} - $starttime{sec}) +
                    (($time{usec} - $starttime{usec}) / 1_000_000.0));
            my $mult = ' ';
            if ($delta > 0) {
                $rate = $pos / $delta;
                if ($rate > 1_000) {
                    $rate /= 1_000.0;
                    $mult = 'K';
                }
                if ($rate > 1_000) {
                    $rate /= 1_000.0;
                    $mult = 'M';
                }
            }
            my $pcnt = ($pos + length($data)) * 100 / $$sresp{$DForkLenKey};
            printf(' %3d%%  |%-25s|  %-28s  %5.2f %sB/sec' . "\r", $pcnt,
                    '*' x ($pcnt * 25 / 100), substr($fileName, 0, 28),
                    $rate, $mult);
            last if $rc != kFPNoErr;
            $pos += length($data);
            %lasttime = %time;
            @time{'sec', 'usec'} = gettimeofday();
        }
        print "\n";
        close($local_fh);
        $rc = $session->FPCloseFork($resp{OForkRefNum});
        if ($rc != kFPNoErr) {
            print 'close attempt failed with code ', $rc, ' (',
                    afp_strerror($rc), ")\n";
        }
        return 1;
    },
    put => sub {
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
        my ($dirID, $fileName) = resolve_path($session, $volID, $curdirnode,
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
        my $rc = $session->FPCreateFile(
                Flag        => 0x80,
                VolumeID    => $volID,
                DirectoryID => $dirID,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != kFPNoErr) {
            print 'Couldn\'t create file on remote server; server returned code ',
                    $rc, ' (', afp_strerror($rc), ")\n";
            return 1;
        }
        my %resp;
        ($rc, %resp) = $session->FPOpenFork(
                VolumeID    => $volID,
                DirectoryID => $dirID,
                AccessMode  => 0x3,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != kFPNoErr) {
            print 'open attempt failed with code ', $rc, ' (',
                    afp_strerror($rc), ")\n";
            return 1;
        }

        my $fileLen = (stat($srcFile))[7];
        local $| = 1;
        my $pos = 0;
        my(%time, %lasttime, %starttime);
        @time{'sec', 'usec'} = gettimeofday();
        %starttime = %time;
        my $total = 0;
        my $wcount = 0;
        while (1) {
            my $data;
            my $rcnt = read($srcFile, $data, 131_072);
            last if $rcnt == 0;
            # try a direct write, and see how far we get; zero-copy is
            # preferred if possible.
            ($rc, $wcount) = &$WriteFn($session,
                    Flag        => kFPStartEndFlag,
                    OForkRefNum => $resp{OForkRefNum},
                    Offset      => 0,
                    ForkData    => \$data);

            while ($wcount < ($total + $rcnt) && $rc == kFPNoErr) {
                my $dchunk = substr($data, $wcount - $total,
                        $total + $rcnt - $wcount);
                ($rc, $wcount) = &$WriteFn($session,
                        Flag        => kFPStartEndFlag,
                        OForkRefNum => $resp{OForkRefNum},
                        Offset      => 0,
                        ForkData    => \$dchunk);
            }
            $total += $rcnt;
#            if ($hashmarks_enabled == 1) {
#            my $pcnt = ($pos + length($data)) * 100 / $fileLen;
#            printf(' %3d%%  |%-25s|  %-.42s' . "\r",
#                    $pcnt, '*' x ($pcnt * 25 / 100), $srcFileName);
            my $rate = 0;
            my $delta = (($time{sec} - $starttime{sec}) +
                    (($time{usec} - $starttime{usec}) / 1_000_000.0));
            my $mult = ' ';
            if ($delta > 0) {
                $rate = $pos / $delta;
                if ($rate > 1_000) {
                    $rate /= 1_000.0;
                    $mult = 'K';
                }
                if ($rate > 1_000) {
                    $rate /= 1_000.0;
                    $mult = 'M';
                }
            }
            my $pcnt = ($pos + length($data)) * 100 / $fileLen;
            printf(' %3d%%  |%-25s|  %-28s  %5.2f %sB/sec' . "\r", $pcnt,
                    '*' x ($pcnt * 25 / 100), $fileName, $rate, $mult);
            last if $rc != kFPNoErr;
            $pos += $rcnt;
            %lasttime = %time;
            @time{'sec', 'usec'} = gettimeofday();
            #}
            unless ($rc == kFPNoErr) {
                print 'Write to file on server failed with return code ', $rc,
                        ' (', afp_strerror($rc), ")\n";
                last;
            }
        }
        #if ($hashmarks_enabled == 1) {
        print "\n";
        #}
        close($srcFile);
        $rc = $session->FPCloseFork($resp{OForkRefNum});
        if ($rc != kFPNoErr) {
            print 'close attempt failed with code ', $rc, ' (',
                    afp_strerror($rc), "\n";
        }
        return 1;
    },
    mkdir   => sub {
        my @words = @_;
        if (scalar(@words) != 2) {
            print <<'_EOT_';
Please specify the name of the directory to create.
_EOT_
            return 1;
        }
        my $rc = $session->FPCreateDir(
                VolumeID    => $volID,
                DirectoryID => $curdirnode,
                PathType    => $pathType,
                Pathname    => $words[1]);
        if ($rc != kFPNoErr) {
            print 'sorry, couldn\'t create requested directory; response was ',
                    $rc, ' (', afp_strerror($rc), ")\n";
        }
        return 1;
    },
    rm  => sub {
        my @words = @_;
        if (scalar(@words) < 2) {
            print <<'_EOT_';
Please specify the name of one or more files or directories to remove.
_EOT_
            return 1;
        }
NEXT_ARG:
        foreach my $item (@words[1 .. $#words]) {
            my $expansion_list = expand_globbed_path($session, $volID, $curdirnode, $words[1]);
            if (!ref($expansion_list) || scalar(@{$expansion_list}) < 1) {
                print "Sorry, couldn't find any matches for entry \"", $item, "\"\n";
                next NEXT_ARG;
            }
NEXT_EXPANDED:
            foreach my $elem (@{$expansion_list}) {
                my ($dirId, $fileName, $dirName) = @{$elem};
                my $rc = $session->FPDelete($volID, $dirId, $pathType,
                        $fileName || q{});
                if ($rc != kFPNoErr) {
                    print 'sorry, couldn\'t remove item "',
                            $fileName || $dirName, '"; response was ', $rc,
                            ' (', afp_strerror($rc), ")\n";
                }
            }
        }
        return 1;
    },
    pwd => sub {
        my @words = @_;
        my $searchID = $curdirnode;
        my @nameParts;
        while ($searchID != $topDirID) {
            my $dirbits = kFPParentDirIDBit | $pathFlag;
            my($rc, $entry) = $session->FPGetFileDirParms(
                    VolumeID        => $volID,
                    DirectoryID     => $searchID,
                    DirectoryBitmap => $dirbits,
                    PathType        => $pathType,
                    Pathname        => q{});
            push(@nameParts, $$entry{$pathkey});
            $searchID = $entry->{ParentDirID};
        }
        print "current directory is /", join('/', reverse(@nameParts)), "\n";
        return 1;
    },
    exit    => sub {
        return;
    },
    get_acl => sub {
        my @words = @_;
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);
            my($rc, %resp) = $session->FPGetACL(
                    VolumeID    => $volID,
                    DirectoryID => $dirId,
                    Bitmap      => kFileSec_UUID | kFileSec_GRPUUID |
                                    kFileSec_ACL,
                    PathType    => $pathType,
                    Pathname    => $fileName);
            if ($rc != kFPNoErr) {
                print "Sorry, file/directory was not found\n";
                return 1;
            }
            print "ACL for \"", $fname, "\":\n";
            print Dumper(\%resp);
        }
        return 1;
    },
    get_comment => sub {
        my @words = @_;
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);
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
    globtest    => sub {
        my @words = @_;
        print Dumper(expand_globbed_path($session, $volID, $curdirnode,
                $words[1]));

        return 1;
    },
    lcd => sub {
        my @words = @_;
        chdir($words[1] || $ENV{HOME}) || print "Couldn't change local directory: $!\n";
        return 1;
    },
    lpwd    => sub {
        print Cwd::getcwd(), "\n";
        return 1;
    },
    'chmod'     => sub {
        my @words = @_;
        if (scalar(@words) < 3) {
            print <<'_EOT_';
ERROR: Not enough arguments. Pass the desired mode (octal), and one or more
files to change the mode of.
_EOT_
            return 1;
        }
        my $mode = oct($words[1]);
    },
    allinfo => sub {
        my @words = @_;
        my $fileBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
                kFPNodeIDBit | $DForkLenFlag | $RForkLenFlag |
                kFPParentDirIDBit | $pathFlag;
        if ($volInfo->{VolAttribute} & kSupportsUnixPrivs) {
            $fileBmp |= kFPUnixPrivsBit;
        }
        my $dirBmp = kFPAttributeBit | kFPCreateDateBit | kFPModDateBit |
                kFPNodeIDBit | kFPOffspringCountBit | kFPOwnerIDBit |
                kFPGroupIDBit | kFPAccessRightsBit | kFPParentDirIDBit |
                $pathFlag;
        if ($volInfo->{VolAttribute} & kSupportsUnixPrivs) {
            $dirBmp |= kFPUnixPrivsBit;
        }
        my($rc, $resp);
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);

            ($rc, $resp) = $session->FPGetFileDirParms(
                    VolumeID        => $volID,
                    DirectoryID     => $dirId,
                    FileBitmap      => $fileBmp,
                    DirectoryBitmap => $dirBmp,
                    PathType        => $pathType,
                    Pathname        => $fileName || q{});
            if ($rc == kFPNoErr) {
                print Dumper($resp);
            }
            else {
                print "ERROR: Could not look up entry \"$fname\", error $rc (",
                        afp_strerror($rc), ")\n";
            }
        }
        return 1;
    },
);
$commands{dir}    = $commands{ls};
$commands{delete} = $commands{rm};
$commands{quit}   = $commands{exit};
$commands{cdup}   = [ $commands{cd}, '..' ];
$commands{rmdir}  = $commands{rm};

binmode STDOUT, ':utf8';
binmode STDIN, ':utf8';

local $SIG{INT} = sub {
    print "\nCtrl-C received, exiting\n";
    $session->FPCloseDT($DT_ID) if defined $DT_ID;
    $session->FPCloseVol($volID);
    $session->FPLogout();
    $session->close();
    exit(0);
};

while (1) {
    my $line = $term->readline('afpsh$ ');
    if (!defined($line)) {
        print "\n";
        last;
    }
    $line = decode($term_enc, $line);
    my @words = shellwords($line);
    next if (!defined($words[0]) || ($words[0] eq q{}));
    if (exists $commands{$words[0]}) {
        my $docall = $commands{$words[0]};
        if (ref($docall) eq 'ARRAY') {
            @words = ($words[0], @{$docall}[1 .. $#{$docall}], @words[1 .. $#words]);
            $docall = $docall->[0];
        }
        my $rv = &{$docall}(@words);
        last unless $rv;
    }
    else {
        print "Sorry, unknown command\n";
    }
}

my %uidmap;
my %gidmap;

sub do_listentries {
    my ($results, $volID) = @_;
    @$results = sort { $$a{$pathkey} cmp $$b{$pathkey} } @$results;
    foreach my $ent (@$results) {
        my $fmodtime = $$ent{ModDate};
        my $tfmt = '%b %e  %Y';
        if (time() - $fmodtime < 6 * 30 * 24 * 60 * 60) {
            $tfmt = '%b %e %H:%M';
        }
        my $up;
        if (exists $$ent{UnixPerms}) {
            $up = $$ent{UnixPerms};
        }
        else {
            $up = $$ent{FileIsDir} ? 0755 : 0644;
        }
        my $uid = $ent->{UnixUID} || $ent->{OwnerID} || 0;
        my $user;
        if (exists $uidmap{$uid}) {
            $user = $uidmap{$uid};
        }
        else {
            $session->FPMapID(kUserIDToName, $uid, \$user);
            $uidmap{$uid} = $user;
        }

        my $gid = $ent->{UnixGID} || $ent->{GroupID} || 0;
        my $group;
        if (exists $gidmap{$gid}) {
            $group = $gidmap{$gid};
        }
        else {
            $session->FPMapID(kGroupIDToName, $gid, \$group);
            $gidmap{$gid} = $group;
        }

        $$ent{$pathkey} =~ tr/\//:/;
        printf('%s%s%s%s%s%s%s%s%s%s %3d %-8s %-8s %8s %-11s %s' . "\n",
            ($ent->{FileIsDir} == 1 ? 'd' : '-'),
            ($up & 0400 ? 'r' : '-'),
            ($up & 0200 ? 'w' : '-'),
            ($up & 04000 ? ($up & 0100 ? 's' : 'S') : ($up & 0100 ? 'x' : '-')),
            ($up & 0040 ? 'r' : '-'),
            ($up & 0020 ? 'w' : '-'),
            ($up & 02000 ? ($up & 0010 ? 's' : 'S') : ($up & 0010 ? 'x' : '-')),
            ($up & 0004 ? 'r' : '-'),
            ($up & 0002 ? 'w' : '-'),
            ($up & 01000 ? ($up & 0001 ? 't' : 'T') : ($up & 0001 ? 'x' : '-')),
            ($ent->{FileIsDir} == 1 ? $ent->{OffspringCount} + 2 : 1),
            $user || $uid, $group || $gid,
            ($ent->{FileIsDir} == 1 ? 0 : $ent->{$DForkLenKey}),
            strftime($tfmt, localtime($fmodtime)),
            $ent->{$pathkey});
        if ($client_uuid) {
            my($rc, %acl_info) = $session->FPGetACL(
                    VolumeID    => $volID,
                    DirectoryID => $ent->{ParentDirID},
                    PathType    => $pathType,
                    Pathname    => $ent->{$pathkey});
            if ($rc == kFPNoErr && ($acl_info{Bitmap} & kFileSec_ACL)) {
                for (my $i = 0; $i <= $#{$acl_info{acl_ace}}; $i++) {
                    my $entry = $acl_info{acl_ace}[$i];
                    my $name;
                    my @args = ();
                    my $rc = $session->FPMapID(kUserUUIDToUTF8Name,
                            $entry->{ace_applicable}, \$name);
                    my $idtype;
                    if ($name->{Bitmap} == kFileSec_UUID) {
                        $idtype = 'user';
                    }
                    elsif ($name->{Bitmap} == kFileSec_GRPUUID) {
                        $idtype = 'group';
                    }

                    my $acl_kind = $entry->{ace_flags} & KAUTH_ACE_KINDMASK;
                    my $kind = 'unknown';
                    if ($acl_kind == KAUTH_ACE_PERMIT) {
                        $kind = 'allow';
                    }
                    elsif ($acl_kind == KAUTH_ACE_DENY) {
                        $kind = 'deny';
                    }

                    my @actions = ();
                    my $rights = $entry->{ace_rights};
                    if ($rights & KAUTH_VNODE_READ_DATA) {
                        push(@actions, $ent->{FileIsDir} ? 'list' : 'read');
                    }
                    if ($rights & KAUTH_VNODE_WRITE_DATA) {
                        push(@actions, $ent->{FileIsDir} ? 'add_file' :
                                'write');
                    }
                    if ($rights & KAUTH_VNODE_EXECUTE) {
                        push(@actions, $ent->{FileIsDir} ? 'search' :
                                'execute');
                    }
                    if ($rights & KAUTH_VNODE_DELETE) {
                        push(@actions, 'delete');
                    }
                    if ($rights & KAUTH_VNODE_APPEND_DATA) {
                        push(@actions, $ent->{FileIsDir} ?
                                'add_subdirectory' : 'append');
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
                            $name->{UTF8Name}, $kind, @actions);
                }
            }
        }
    }
    return;
}

sub expand_globbed_path {
    my ($session, $volid, $dirid, $path) = @_;

    my $dirBmp = kFPNodeIDBit | kFPParentDirIDBit | $pathFlag;
    my $fileBmp = $dirBmp;
    my $fileName = undef;
    my @pathElements = split('/', $path);
    my $curNode = $dirid;

    my @nameParts;

    if (!defined($pathElements[0]) || ($pathElements[0] eq q{})) {
        $curNode = 2;
        shift(@pathElements);
    }
    else {
        my $searchID = $curNode;
        while ($searchID != $topDirID) {
            my $dirbits = kFPParentDirIDBit | $pathFlag;
            my($rc, $entry) = $session->FPGetFileDirParms(
                    VolumeID        => $volID,
                    DirectoryID     => $searchID,
                    DirectoryBitmap => $dirbits,
                    PathType        => $pathType,
                    Pathname        => q{});
            unshift(@nameParts, $entry->{$pathkey});
            $searchID = $entry->{ParentDirID};
        }
    }
    my @expanded_paths = ( [ $curNode, q{}, @nameParts ] );
    my $pathElem = shift(@pathElements);
    while (defined $pathElem) {
        my (@newpaths);
        if ($pathElem eq q{} or $pathElem eq q{.}) {
            $pathElem = shift(@pathElements);
            next;
        }
        if ($pathElem eq q{..}) {
            # use unique keyspace temporarily for duplicate checking, since
            # I think this is really the only point where it's a serious
            # concern (so far).
            my %dupchk;
            foreach my $expath (@expanded_paths) {
                next if $$expath[1] ne q{};
                my($rc, $resp) = $session->FPGetFileDirParms(
                        VolumeID        => $volid,
                        DirectoryID     => $$expath[0],
                        DirectoryBitmap => kFPParentDirIDBit,
                        PathType        => $pathType,
                        Pathname        => q{});
                next if $rc != kFPNoErr;
                next if exists $dupchk{$resp->{ParentDirID}};
                push(@newpaths, [ $resp->{ParentDirID}, q{},
                        @{$expath}[3 .. $#{$expath}] ]);
                $dupchk{$resp->{ParentDirID}} = 1;
            }
            @expanded_paths = @newpaths;
            $pathElem = shift(@pathElements);
            next;
        }
        $pathElem =~ tr/:/\//;
        foreach my $expath (@expanded_paths) {
            my ($rc, $resp, %entries);
            $rc = kFPNoErr;
            my $lastelem;
COLLECT_PATHS:
            while ($rc == kFPNoErr){
                ($rc, $resp) = &$EnumFn($session,
                               VolumeID         => $volid,
                               DirectoryID      => $$expath[0],
                               FileBitmap       => $fileBmp,
                               DirectoryBitmap  => $dirBmp,
                               ReqCount         => 256,
                               StartIndex       => scalar(keys %entries) + 1,
                               MaxReplySize     => 32767,
                               PathType         => $pathType,
                               Pathname         => $$expath[1]);
                if ($rc == kFPNoErr || $rc == kFPObjectNotFound) {
                    if ($#{$resp} == 0 && $lastelem &&
                            $resp->[0]->{$pathkey} eq $lastelem) {
                        last COLLECT_PATHS;
                    }
                    foreach my $elem (@{$resp}) {
                        $entries{$$elem{$pathkey}} = $elem;
                    }
                    if ($#{$resp} > -1) {
                        $lastelem = $resp->[$#{$resp}]->{$pathkey};
                    }
                }
            }
            my @matches = sort {$a cmp $b} match_glob($pathElem,
                    keys(%entries));
            foreach my $match (@matches) {
                $match =~ tr/\//:/;
                my $nelem = [];
                if ($entries{$match}{FileIsDir}) {
                    @$nelem = ($entries{$match}{NodeID}, q{}, $match,
                            @$expath[2 .. $#$expath]);
                } else {
                    @$nelem = ($$expath[0], $match, @$expath[2 .. $#$expath]);
                }
                push(@newpaths, $nelem);
            }
        }
        @expanded_paths = @newpaths;

        $pathElem = shift(@pathElements);
    }

    return [ @expanded_paths ];
}

# $lastIfDir - the last element can be a directory; needed for removing
# directories, like for FPRemove
# $lastNoExist - the last element might not exist, like for FPCreateFile (i.e.,
# for use as part of the "put" command)
sub resolve_path {
    my ($session, $volid, $dirid, $path, $lastIfDir, $lastNoExist) = @_;

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
    my $curNode = $dirid;
    if (!defined($pathElements[0]) || ($pathElements[0] eq q{})) {
        $curNode = 2;
        shift(@pathElements);
    }
    for (my $i = 0; $i < scalar(@pathElements); $i++) {
        my $elem = $pathElements[$i];
        my $getParentID = 0;
        next if $elem eq q{.} or $elem eq q{};
        if ($elem eq q{..}) {
            next if $curNode == 2;
            $elem = q{};
            $getParentID = 1;
        }
        $elem =~ tr/:/\//;
        my($rc, $resp) = $session->FPGetFileDirParms(
                VolumeID        => $volid,
                DirectoryID     => $curNode,
                FileBitmap      => $fileBmp,
                DirectoryBitmap => $dirBmp,
                PathType        => $pathType,
                Pathname        => $elem);
        if (($lastNoExist == 1 and $rc == kFPObjectNotFound) or
                ($rc == kFPNoErr and $resp->{FileIsDir} != 1)) {
            if ($i == $#pathElements) {
                $fileName = $elem;
                last;
            }
            else {
                return(undef);
            }
        }
        return(undef) if $rc != kFPNoErr;
        $curNode = ($getParentID == 1 ? $resp->{ParentDirID} :
                $resp->{NodeID});
    }
    return($curNode, $fileName);
}

$session->FPCloseDT($DT_ID) if defined $DT_ID;
$session->FPCloseVol($volID);
$session->FPLogout();
$session->close();
exit(0);


# vim: ts=4 et ai
