#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;
use English qw(-no_match_vars);
use Module::Load;

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

# Pull in all the AFP packages that we need, for the connection object
# itself and return code symbols, helper functions for version handling
# and UAMs, etc.
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
use Log::Log4perl;

use Term::ReadLine;     # for reading input from user

use IO::File;
use Text::ParseWords;   # for "shell" style command parsing
use Getopt::Long qw(GetOptionsFromArray);
                        # for command-line option parsing
use Data::Dumper;       # for debugging; remove later
use POSIX;              # for POSIX time handling
use File::Basename;
if ($OSNAME eq q{MSWin32}) {
    require Term::ReadPassword::Win32;
    Term::ReadPassword::Win32->import;
}
else {
    require Term::ReadPassword;
    Term::ReadPassword->import;
}
use Time::HiRes qw(gettimeofday);
use Text::Glob qw(match_glob);
use Encode;
use I18N::Langinfo qw(langinfo CODESET);
use Cwd();
use Fcntl qw(:mode);

# Find out the character encoding for the current terminal.
my $term_enc = langinfo(CODESET);
my $blksize  = 1<<19;

# If you're in Windows, you'll probably just get a codepage number.
if ($OSNAME eq q{MSWin32} && $term_enc =~ m{^\d+$}sm) {
    $term_enc = q{cp} . $term_enc;
}

my $has_Term__ReadKey = 0;
eval { require Term::ReadKey; 1; } and do {
    Term::ReadKey->import;
    $has_Term__ReadKey = 1;
};

my $has_UUID = 0;
eval { require UUID; 1; } and do { $has_UUID = 1; };

my $has_Archive__Tar = 1;
eval { require Archive::Tar; 1; } or do {
    print {*STDERR} qq{WARNING: Sorry, Archive::Tar not available.\n};
    $has_Archive__Tar = 0;
};

sub usage {
    print <<"_EOT_";

afpclient version ${Net::AFP::VERSION} - Apple Filing Protocol CLI client

Usage: ${PROGRAM_NAME} [options] [AFP URL]

Options:
    --atalk-first
        Use AppleTalk transport before IP transport, if available; normally
        IP transport is used first, for performance reasons.
    -4|--prefer-v4
        Use IPv4 connectivity before IPv6, if available.
    --debug-afp
        Turn on debug output for the AFP module.
    --debug-dsi
        Turn on debug output for the DSI module.
    --sendfile-impl [implementation]
        Override the sendfile implementation used. Mainly for testing
        purposes. If a sendfile implementation is specified that isn't
        known, it will cause a failure.
    --help
        This help summary.

AFP URL format:

afp://[<user>[;AUTH=<uam>][:<password>]@]<host>[:<port>]/<share>[/<path>]
afp:/at/[<user>[;AUTH=<uam>][:<password>]@]<host>[:<zone>]/<share>[/<path>]

Items in [] are optional; they are as follows:

  <user>     : Your username on the remote system
  <uam>      : The auth method to force with the server
  <password> : Your password on the remote system
  <host>     : Hostname or IP address of the target server, IPv6 addresses
               can be specified in square brackets
  <zone>     : An AppleTalk zone name, or * for the local zone
  <port>     : The port on the server to connect to
  <share>    : The name of the exported share on the remote system
  <path>     : A subpath inside the specified share to mount

_EOT_
    exit 1;
}

my %afpopts;
my($atalk_first, $prefer_v4, $debug_afp, $debug_dsi, $sendfile_impl);
Getopt::Long::Configure(q{no_ignore_case});
GetOptions( q{atalk-first}     => \$atalk_first,
            q{4|prefer-v4}     => \$prefer_v4,
            q{debug-afp}       => \$debug_afp,
            q{debug-dsi}       => \$debug_dsi,
            q{sendfile-impl=s} => \$sendfile_impl,
            q{h|help}          => \&usage) || usage();

if (defined $sendfile_impl and $sendfile_impl ne q{}) {
    load Net::AFP::Helpers, sendfile_only => $sendfile_impl;
}
else {
    load Net::AFP::Helpers;
    Net::AFP::Helpers->import();
}

my $logconf = <<'_EOT_';
log4perl.appender.AppLogging = Log::Log4perl::Appender::Screen
log4perl.appender.AppLogging.layout = PatternLayout
log4perl.appender.AppLogging.layout.ConversionPattern = [%P] %F line: %L %c - %m%n
log4perl.appender.AppLogging.Threshold = INFO

log4perl.appender.Console = Log::Log4perl::Appender::ScreenColoredLevels
log4perl.appender.Console.layout = SimpleLayout

log4perl.logger = INFO, AppLogging
_EOT_

if (defined $debug_afp) {
    $logconf .= <<'_EOT_';
log4perl.logger.Net.AFP = DEBUG, Console
_EOT_
}

if (defined $debug_dsi) {
    $logconf .= <<'_EOT_';
log4perl.logger.Net.DSI = DEBUG, Console
_EOT_
}
Log::Log4perl->init(\$logconf);

$afpopts{aforder} = [AF_INET];
if ($prefer_v4) {
    push @{$afpopts{aforder}}, AF_INET6;
} else {
    unshift @{$afpopts{aforder}}, AF_INET6;
}
if ($atalk_first) {
    unshift @{$afpopts{aforder}}, AF_APPLETALK;
} else {
    push @{$afpopts{aforder}}, AF_APPLETALK;
}

if (not scalar @ARGV) {
    usage();
}

my($url) = @ARGV;

my $pw_cb = sub {
    my(%values) = @_;
    my $prompt = q{Password: };
    return $values{password} if defined $values{password};
    return read_password($prompt);
};
my($session, %values) = do_afp_connect($pw_cb, $url || q{}, undef, %afpopts);
if (not ref $session or not $session->isa(q{Net::AFP})) {
    exit $session;
}

# If no volume was named, contact the server and find out the volumes
# it knows, and spit those out in a friendly format.
if (not $values{volume}) {
    my $srvrParms;
    $session->FPGetSrvrParms(\$srvrParms);
    print <<'_EOT_';

Volume Name                                 | UNIX privs? | Volume pass?
-------------------------------------------------------------------------
_EOT_
    foreach my $volume (@{$srvrParms->{Volumes}}) {
        printf qq{%-43s |     %-3s     |     %s\n}, $volume->{VolName},
                $volume->{HasUNIXPrivs} ? q{Yes} : q{No},
                $volume->{HasPassword} ? q{Yes} : q{No};
    }

    $session->FPLogout();
    $session->close();
    exit 0;
}

my $volInfo;
my $ret = $session->FPOpenVol($kFPVolAttributeBit,
        decode($term_enc, $values{volume}), undef, \$volInfo);
if ($ret != $kFPNoErr) {
    print {*STDERR} qq{ERROR: Volume was unknown?\n};
    $session->FPLogout();
    $session->close();
    exit 1;
}

my $volID = $volInfo->{ID};
my $DT_ID;
$ret = $session->FPOpenDT($volID, \$DT_ID);
if ($ret != $kFPNoErr) {
    print {*STDERR} qq{WARNING: Couldn't open Desktop DB\n};
    undef $DT_ID;
}

my $volAttrs = $volInfo->{Attribute};

my $client_uuid;
if ($volAttrs & $kSupportsACLs) {
    if ($has_UUID) {
        $client_uuid = UUID::uuid();
    }
    else {
        print {*STDERR} qq{WARNING: Need UUID class for full ACL } .
          qq{functionality, ACL checking disabled\n};
    }
}

my $pathType    = $kFPLongName;
my $pathFlag    = $kFPLongNameBit;
my $pathkey     = q{LongName};

if ($volAttrs & $kSupportsUTF8Names) {
    # If the remote volume does UTF8 names, then we'll go with that..
    $pathType       = $kFPUTF8Name;
    $pathFlag       = $kFPUTF8NameBit;
    $pathkey        = q{UTF8Name};
}

my $topDirID = 2;
my $term = Term::ReadLine->new(q{afpclient});
my $attribs = $term->Attribs();
my $curdirnode = $topDirID;

my $DForkLenFlag    = $kFPDataForkLenBit;
my $RForkLenFlag    = $kFPRsrcForkLenBit;
my $DForkLenKey     = q{DataForkLen};
my $RForkLenKey     = q{RsrcForkLen};
my $EnumFn          = \&Net::AFP::FPEnumerate;
my $ReadFn          = \&Net::AFP::FPRead;
my $WriteFn         = \&Net::AFP::FPWrite;
my $MaxReplySize    = 0x7FFF;
# I *think* large file support entered the picture as of AFP 3.0...
if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
        $kFPVerAtLeast)) {
    $DForkLenFlag   = $kFPExtDataForkLenBit;
    $RForkLenFlag   = $kFPExtRsrcForkLenBit;
    $DForkLenKey    = q{ExtDataForkLen};
    $RForkLenKey    = q{ExtRsrcForkLen};
    $ReadFn         = \&Net::AFP::FPReadExt;
    $WriteFn        = \&Net::AFP::FPWriteExt;
    $EnumFn         = \&Net::AFP::FPEnumerateExt;
}

if (Net::AFP::Versions::CompareByVersionNum($session, 3, 1,
        $kFPVerAtLeast)) {
    $EnumFn         = \&Net::AFP::FPEnumerateExt2;
    $MaxReplySize   = 0x3FFFF;
}

if (defined $values{subpath}) {
    my ($newDirId, $fileName) = resolve_path($session, $volID, $curdirnode,
            decode($term_enc, $values{subpath}));
    if (defined $fileName || !defined $newDirId) {
        printf {*STDERR} q{WARNING: path %s is not accessible, defaulting } .
                qq{to volume root\n}, $values{subpath};
    }
    else {
        $curdirnode = $newDirId;
    }
}

my %commands = (
    ls  => sub {
        my @words = @_;
        my $fileBmp = $kFPAttributeBit | $kFPCreateDateBit | $kFPModDateBit |
                $kFPNodeIDBit | $DForkLenFlag | $RForkLenFlag |
                $kFPParentDirIDBit | $pathFlag;
        if ($volInfo->{Attribute} & $kSupportsUnixPrivs) {
            $fileBmp |= $kFPUnixPrivsBit;
        }
        my $dirBmp = $kFPAttributeBit | $kFPCreateDateBit | $kFPModDateBit |
                $kFPNodeIDBit | $kFPOffspringCountBit | $kFPOwnerIDBit |
                $kFPGroupIDBit | $kFPAccessRightsBit | $kFPParentDirIDBit |
                $pathFlag;
        if ($volInfo->{Attribute} & $kSupportsUnixPrivs) {
            $dirBmp |= $kFPUnixPrivsBit;
        }
        my $printDirNames = 0;
        if (scalar(@words) > 2) {
            $printDirNames = 1;
        }
        if (scalar(@words) < 2) {
            push @words, q{.};
        }
        foreach my $item (@words[1 .. $#words]) {
            my $results;
            my $rc;
            my $expansion_list = expand_globbed_path($session, $volID, $curdirnode, $item);
            if (!ref($expansion_list) || scalar(@{$expansion_list}) < 1) {
                printf qq{Sorry, couldn't find any matches for entry "%s"\n}, $item;
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
                    if ($rc == $kFPNoErr) {
                        push @records, $resp;
                    }
                }
                else {
                    my $offset = 1;
                    do {
                        $results = undef;
                        ($rc, $results) = &{$EnumFn}($session,
                                VolumeID        => $volID,
                                DirectoryID     => $dirId,
                                FileBitmap      => $fileBmp,
                                DirectoryBitmap => $dirBmp,
                                ReqCount        => 1024,
                                StartIndex      => $offset,
                                MaxReplySize    => $MaxReplySize,
                                PathType        => $pathType,
                                Pathname        => q{});
                        if (ref($results) eq q{ARRAY}) {
                            push @records, @{$results};
                            $offset += scalar @{$results};
                        }
                    ##no critic qw(ProhibitPostfixControls)
                    } while ($rc == $kFPNoErr);
                }
                if ($rc == $kFPNoErr || $rc == $kFPObjectNotFound) {
                    if ($printDirNames == 1 &&
                            (!defined($fileName) || $fileName eq q{})) {
                        print $dirName, qq{:\n};
                    }
                    do_listentries(\@records, $volID);
                    if ($printDirNames == 1 &&
                            (!defined($fileName) || $fileName eq q{})) {
                        print qq{\n};
                    }
                }
            }
        }
        return 1;
    },
    cat => sub {
        my @words = @_;
        STDOUT->autoflush(1);
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);
            my ($rc, %resp) = $session->FPOpenFork(
                    VolumeID    => $volID,
                    DirectoryID => $dirId,
                    AccessMode  => $kFPAccessReadOnly,
                    PathType    => $pathType,
                    Pathname    => $fileName);
            if ($rc != $kFPNoErr) {
                printf qq{ERROR: Open attempt failed with code %d (%s)\n}, $rc,
                  afp_strerror($rc);
                next;
            }
            my $pos = 0;
            while (1) {
                my $data;
                ($rc, $data) = &{$ReadFn}($session,
                        OForkRefNum => $resp{OForkRefNum},
                        Offset      => $pos,
                        ReqCount    => 1024);
                last if $rc != $kFPNoErr and $rc != $kFPEOFErr;
                print ${$data};
                $pos += length ${$data};
                last if $rc == $kFPEOFErr;
            }
            $rc = $session->FPCloseFork($resp{OForkRefNum});
            if ($rc != $kFPNoErr) {
                printf qq{ERROR: Close attempt failed with code %d (%s)\n},
                  $rc, afp_strerror($rc);
            }
        }
        return 1;
    },
    cd  => sub {
        my @words = @_;
        my $path;
        if (scalar(@words) == 1) {
            $path = q{/};
        }
        elsif (scalar(@words) == 2) {
            $path = $words[1];
        }
        else {
            print qq{Incorrect number of arguments\n};
            return 1;
        }
        my ($newDirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                $path);
        if (defined $fileName || !defined $newDirId) {
            print qq{sorry, couldn't change directory\n};
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
            c      => \$continue,
            E      => \$del_src_after_get,
            e      => \$del_target_before_get,
            q{O=s} => \$basedir,
            q{o=s} => \$outputpath,
        ); # should print usage and return if this doesn't succeed
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
        if (not defined $dirId) {
            print <<'_EOT_';
Error: Couldn't resolve path; possibly no such file?
_EOT_
            return 1;
        }
        if (not defined $fileName) {
            print <<'_EOT_';
Error: Not a file; you must specify the name of a file to retrieve.
_EOT_
            return 1;
        }
        my $targetFile = (scalar(@words) == 1 ? $fileName : $words[1]);
        my($rc, %resp) = $session->FPOpenFork(
                VolumeID    => $volID,
                DirectoryID => $dirId,
                AccessMode  => $kFPAccessReadOnly,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Open attempt failed with code %d (%s)\n}, $rc,
              afp_strerror($rc);
            return 1;
        }

        my $local_fh = IO::File->new($targetFile, q{w});
        if (not defined $local_fh) {
            print qq{Couldn't open local file for writing!\n};
            $session->FPCloseFork($resp{OForkRefNum});
            return 1;
        }
        binmode $local_fh;
        truncate $local_fh, 0;

        my $sresp = q{};
        my $bitmap = $DForkLenFlag | $RForkLenFlag;
        ($rc, $sresp) = $session->FPGetFileDirParms(
                VolumeID    => $volID,
                DirectoryID => $dirId,
                PathType    => $pathType,
                Pathname    => $fileName,
                FileBitmap  => $bitmap);

        if ($sresp->{$RForkLenKey} > 0) {
            print qq{note that the resource fork isn't handled yet!\n};
        }
        my $len = $sresp->{$DForkLenKey};
        STDOUT->autoflush(1);
        my $pos = 0;
        my($time, $lasttime, $starttime, $data, $rate, $delta, $mult, $pcnt,
          $twidth, $rlen, $lastpos);
        $twidth = 80; # if we can't ascertain, go with safe default
        $starttime = $time = gettimeofday();
        $lasttime = 0;
        $lastpos = 0;
        $pcnt = 0;

        while (1) {
            $rlen = $blksize;
            if ($pos + $blksize > $len) {
                $rlen = $len - $pos;
                last if $rlen == 0;
            }
            ($rc, $data) = &{$ReadFn}($session,
                    OForkRefNum => $resp{OForkRefNum},
                    Offset      => $pos,
                    ReqCount    => $rlen);
            last if $rc != $kFPNoErr and $rc != $kFPEOFErr;
            syswrite $local_fh, ${$data};
            $pos += $rlen;
            $time = gettimeofday();
            if (($time - $lasttime > 0.5) or $rc != $kFPNoErr or $pos >= $len) {
                $pcnt = $pos * 100 / $len;
                if ($pcnt == 100) {
                    $delta = $time - $starttime;
                }
                else {
                    $delta = $time - $lasttime;
                }
                $rate = 0;
                $mult = q{ };
                if ($delta > 0) {
                    if ($pcnt == 100) {
                        $rate = $pos / $delta;
                    }
                    else {
                        $rate = ($pos - $lastpos) / $delta;
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{K};
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{M};
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{G};
                    }
                }
                if ($has_Term__ReadKey) {
                    $twidth = (GetTerminalSize())[0];
                }
                printf qq{\r %3d%%  |%-25s|  %-} . ($twidth - 52) . q{s  %5.2f %sB/sec},
                  $pcnt, q{*} x ($pcnt * 25 / 100),
                  substr($fileName, 0, $twidth - 52), $rate, $mult;
                $lasttime = $time;
                $lastpos = $pos;
                last if $rc != $kFPNoErr;
            }
        }
        printf qq{\nTransferred %d bytes in %dh%dm%.2fs\n}, $pos, $delta / 3600,
          $delta / 60 % 60, $delta - (int(int($delta) / 60) * 60);
        close($local_fh) || carp(q{Couldn't close local file});
        $rc = $session->FPCloseFork($resp{OForkRefNum});
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Close attempt failed with code %d (%s)\n}, $rc,
              afp_strerror($rc);
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
        if (not defined $dirID) {
            print <<'_EOT_';
Error: Couldn't resolve path; possibly no such file?
_EOT_
            return 1;
        }
        if (not defined $fileName) {
            $fileName = $srcFileName;
        }

        my $srcFile = IO::File->new($words[1], q{r});
        if (not defined $srcFile) {
            print qq{couldn't open source file\n};
            return 1;
        }
        binmode $srcFile;
        my $rc = $session->FPCreateFile(
                Flag        => $kFPHardCreate,
                VolumeID    => $volID,
                DirectoryID => $dirID,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Couldn't create file on remote server; server } .
              q{returned code %d (%s)\n}, $rc, afp_strerror($rc);
            return 1;
        }
        my %resp;
        ($rc, %resp) = $session->FPOpenFork(
                VolumeID    => $volID,
                DirectoryID => $dirID,
                AccessMode  => $kFPAccessReadWrite,
                PathType    => $pathType,
                Pathname    => $fileName);
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Open attempt failed with code %d (%s)\n}, $rc,
              afp_strerror($rc);
            return 1;
        }

        my $fileLen = (stat $srcFile)[7];
        STDOUT->autoflush(1);
        my($time, $lasttime, $starttime, $rate, $delta, $mult, $pcnt, $twidth,
          $wcount, $lastpos);
        $twidth = 80; # if we can't ascertain, go with safe default
        $starttime = $time = gettimeofday();
        $lasttime = 0;
        $wcount = 0;
        $lastpos = 0;
        $pcnt = 0;
        while (1) {
            # try a direct write, and see how far we get; zero-copy is
            # preferred if possible.
            my $wsize = $blksize;
            if ($fileLen - $wcount < $wsize) {
                $wsize = $fileLen - $wcount;
            }
            ($rc, $wcount) = &{$WriteFn}($session,
                    Flag        => $kFPStartEndFlag,
                    OForkRefNum => $resp{OForkRefNum},
                    Offset      => 0,
                    FromFH      => $srcFile,
                    ReqCount    => $wsize);

            $time = gettimeofday();
            if (($time - $lasttime > 0.5) || $fileLen <= $wcount) {
                $pcnt = $wcount * 100 / $fileLen;
                if ($pcnt == 100) {
                    $delta = $time - $starttime;
                }
                else {
                    $delta = $time - $lasttime;
                }
                $rate = 0;
                $mult = q{ };
                if ($delta > 0) {
                    if ($pcnt == 100) {
                        $rate = $wcount / $delta;
                    }
                    else {
                        $rate = ($wcount - $lastpos) / $delta;
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{K};
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{M};
                    }
                    if ($rate > 1_000) {
                        $rate /= 1_000.0;
                        $mult = q{G};
                    }
                }
                if ($has_Term__ReadKey) {
                    $twidth = (GetTerminalSize())[0];
                }
                printf qq{\r %3d%%  |%-25s|  %-} . ($twidth - 52) .
                  q{s  %5.2f %sB/sec}, $pcnt, q{*} x ($pcnt * 25 / 100),
                  substr($fileName, 0, $twidth - 52), $rate, $mult;
                $lasttime = $time;
                $lastpos = $wcount;
            }
            if ($rc != $kFPNoErr) {
                printf q{ERROR: Write to file on server failed with } .
                  q{return code %d (%s)\n}, $rc, afp_strerror($rc);
                last;
            }
            last if $rc != $kFPNoErr or $fileLen <= $wcount;
        }
        printf qq{\nTransferred %d bytes in %dh%dm%.2fs\n}, $wcount, $delta / 3600,
          $delta / 60 % 60, $delta - (int(int($delta) / 60) * 60);
        close($srcFile) || carp(q{Couldn't close local file});
        $rc = $session->FPCloseFork($resp{OForkRefNum});
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Close attempt failed with code %d (%s)\n},
              $rc, afp_strerror($rc);
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
        if ($rc != $kFPNoErr) {
            printf qq{ERROR: Couldn't create requested directory; } .
              q{response was %d (%s)\n}, $rc, afp_strerror($rc);
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
                printf qq{Sorry, couldn't find any matches for entry "%s"\n},
                  $item;
                next NEXT_ARG;
            }
NEXT_EXPANDED:
            foreach my $elem (@{$expansion_list}) {
                my ($dirId, $fileName, $dirName) = @{$elem};
                my $rc = $session->FPDelete($volID, $dirId, $pathType,
                        $fileName || q{});
                if ($rc != $kFPNoErr) {
                    printf qq{ERROR: Couldn't remove item "%s"; response } .
                      q{was %d (%s)\n}, $fileName || $dirName, $rc,
                      afp_strerror($rc);
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
            my $dirbits = $kFPParentDirIDBit | $pathFlag;
            my($rc, $entry) = $session->FPGetFileDirParms(
                    VolumeID        => $volID,
                    DirectoryID     => $searchID,
                    DirectoryBitmap => $dirbits,
                    PathType        => $pathType,
                    Pathname        => q{});
            push @nameParts, $entry->{$pathkey};
            $searchID = $entry->{ParentDirID};
        }
        printf q{current directory is /%s\n}, join(q{/}, reverse @nameParts);
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
                    Bitmap      => $kFileSec_UUID | $kFileSec_GRPUUID |
                                    $kFileSec_ACL,
                    PathType    => $pathType,
                    Pathname    => $fileName);
            if ($rc != $kFPNoErr) {
                print qq{Sorry, file/directory was not found\n};
                return 1;
            }
            printf qq{ACL for "%s":\n}, $fname;
            print Dumper(\%resp);
        }
        return 1;
    },
    get_comment => sub {
        my @words = @_;
        foreach my $fname (@words[1..$#words]) {
            my ($dirId, $fileName) = resolve_path($session, $volID, $curdirnode,
                    $fname);
            if (not defined $DT_ID) {
                next;
            }
            my($rc, $resp) = $session->FPGetComment(
                    DTRefNum => $DT_ID,
                    DirectoryID => $dirId,
                    PathType => $pathType,
                    Pathname => $fileName);
            if ($rc != $kFPNoErr) {
                print qq{Sorry, file/directory was not found\n};
                return 1;
            }
            printf qq{Comment for "%s":\n%s\n}, $fname, $resp;
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
        chdir($words[1] || $ENV{HOME}) ||
          printf qq{Couldn't change local directory: %d\n}, $ERRNO;
        return 1;
    },
    lpwd    => sub {
        print Cwd::getcwd(), qq{\n};
        return 1;
    },
    chmod     => sub {
        my @words = @_;
        if (scalar(@words) < 3) {
            print <<'_EOT_';
ERROR: Not enough arguments. Pass the desired mode (octal), and one or more
files to change the mode of.
_EOT_
            return 1;
        }
        my $mode = oct $words[1];
    },
    allinfo => sub {
        my @words = @_;
        my $fileBmp = $kFPAttributeBit | $kFPCreateDateBit | $kFPModDateBit |
                $kFPNodeIDBit | $DForkLenFlag | $RForkLenFlag |
                $kFPParentDirIDBit | $pathFlag;
        if ($volInfo->{Attribute} & $kSupportsUnixPrivs) {
            $fileBmp |= $kFPUnixPrivsBit;
        }
        my $dirBmp = $kFPAttributeBit | $kFPCreateDateBit | $kFPModDateBit |
                $kFPNodeIDBit | $kFPOffspringCountBit | $kFPOwnerIDBit |
                $kFPGroupIDBit | $kFPAccessRightsBit | $kFPParentDirIDBit |
                $pathFlag;
        if ($volInfo->{Attribute} & $kSupportsUnixPrivs) {
            $dirBmp |= $kFPUnixPrivsBit;
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
            if ($rc == $kFPNoErr) {
                print Dumper($resp);
            }
            else {
                printf qq{ERROR: Couldn't look up entry "%s", error %d } .
                  q{(%s)\n}, $fname, $rc, afp_strerror($rc);
            }
        }
        return 1;
    },
);
$commands{dir}    = $commands{ls};
$commands{delete} = $commands{rm};
$commands{quit}   = $commands{exit};
$commands{cdup}   = [ $commands{cd}, q{..} ];
$commands{rmdir}  = $commands{rm};

binmode STDOUT, q{:encoding(UTF-8)};
binmode STDIN, q{:encoding(UTF-8)};

local $SIG{INT} = sub {
    print qq{\nCtrl-C received, exiting\n};
    if (defined $DT_ID) {
        $session->FPCloseDT($DT_ID);
    }
    $session->FPCloseVol($volID);
    $session->FPLogout();
    $session->close();
    exit 0;
};

# Tab completion nonsense, or at least my still-early attempts at it.
if (Term::ReadLine->ReadLine() eq q{Term::ReadLine::Perl} ||
    Term::ReadLine->ReadLine() eq q{Term::ReadLine::Gnu}) {
    $attribs->{completion_function} = sub {
        my ($text, $line, $start) = @_;
        if ($start == 0) {
            # try to expand commands
            my @matches = grep { m{^$text}sm } keys %commands;
            return @matches;
        }
        my $list = expand_globbed_path($session, $volID, $curdirnode, $text . q{*});
        my @reallist = map { my $rv = $_->[1] ne q{} ? $_->[1] : $_->[2] . q{/}; $rv =~ s{ }{\\ }gsm; $rv; } @{$list};
        my $prefix = q{};
        if ($text =~ m{^(.+/)}sm) {
            $prefix = $1;
        }
        if (scalar(@reallist) == 1 && $reallist[0] =~ m{/$}sm) {
            if (Term::ReadLine->ReadLine() eq q{Term::ReadLine::Gnu}) {
                $attribs->{completion_append_character} = q{};
            }
            else {
                ##no critic qw(ProhibitPackageVars)
                $readline::rl_completer_terminator_character = q{};
            }
        } else {
            if (Term::ReadLine->ReadLine() eq q{Term::ReadLine::Gnu}) {
                $attribs->{completion_append_character} = q{ };
            }
            else {
                ##no critic qw(ProhibitPackageVars)
                $readline::rl_completer_terminator_character = q{ };
            }
        }
        return map { $prefix . $_ } @reallist;
    };
}
else {
    print {*STDERR} qq{WARNING: ReadLine implementation doesn't support tab expands\n};
}

while (1) {
    my @nameParts;
    my $searchID = $curdirnode;
    while ($searchID != $topDirID) {
        my $dirbits = $kFPParentDirIDBit | $pathFlag;
        my($rc, $entry) = $session->FPGetFileDirParms(
                VolumeID        => $volID,
                DirectoryID     => $searchID,
                DirectoryBitmap => $dirbits,
                PathType        => $pathType,
                Pathname        => q{});
        push @nameParts, $entry->{$pathkey};
        $searchID = $entry->{ParentDirID};
    }

    my $line = $term->readline(q{afpclient } . (exists $values{username} ? $values{username} . q{@} : q{}) . $values{host} . q{:} . $values{volume} . q{/} . join(q{/}, reverse @nameParts) . q{> });
    if (not defined $line) {
        print qq{\n};
        last;
    }
    $line = decode($term_enc, $line);
    my @words = shellwords($line);
    next if (!defined($words[0]) || ($words[0] eq q{}));
    if (exists $commands{$words[0]}) {
        my $docall = $commands{$words[0]};
        if (ref($docall) eq q{ARRAY}) {
            @words = ($words[0], @{$docall}[1 .. $#{$docall}], @words[1 .. $#words]);
            $docall = $docall->[0];
        }
        my $rv = &{$docall}(@words);
        if (not $rv) {
            last;
        }
    }
    else {
        print qq{Sorry, unknown command\n};
    }
}

my %uidmap;
my %gidmap;

sub do_listentries {
    my ($results, $vol) = @_;
    @{$results} = sort { $a->{$pathkey} cmp $b->{$pathkey} } @{$results};
    foreach my $ent (@{$results}) {
        my $fmodtime = $ent->{ModDate};
        my $tfmt = q{%b %e  %Y};
        if (time() - $fmodtime < 6 * 30 * 24 * 60 * 60) {
            $tfmt = q{%b %e %H:%M};
        }
        my $up;
        if (exists $ent->{UnixPerms}) {
            $up = $ent->{UnixPerms};
        }
        else {
            $up = $ent->{FileIsDir} ?  (S_IFDIR | oct 755) : (S_IFREG | oct 644);
        }
        my $uid = $ent->{UnixUID} || $ent->{OwnerID} || 0;
        my $user;
        if (exists $uidmap{$uid}) {
            $user = $uidmap{$uid};
        }
        else {
            $session->FPMapID($kUserIDToName, $uid, \$user);
            $uidmap{$uid} = $user;
        }

        my $gid = $ent->{UnixGID} || $ent->{GroupID} || 0;
        my $group;
        if (exists $gidmap{$gid}) {
            $group = $gidmap{$gid};
        }
        else {
            $session->FPMapID($kGroupIDToName, $gid, \$group);
            $gidmap{$gid} = $group;
        }

        $ent->{$pathkey} =~ tr/\//:/;
        printf q{%s%s%s%s%s%s%s%s%s%s %3d %-8s %-8s %10d %-11s %s},
            ($ent->{FileIsDir} == 1 ? q{d} : S_ISLNK($up) ? q{l} : q{-}),
            ($up & S_IRUSR ? q{r} : q{-}),
            ($up & S_IWUSR ? q{w} : q{-}),
            ($up & S_ISUID ? ($up & S_IXUSR ? q{s} : q{S}) :
                           ($up & S_IXUSR ? q{x} : q{-})),
            ($up & S_IRGRP ? q{r} : q{-}),
            ($up & S_IWGRP ? q{w} : q{-}),
            ($up & S_ISGID ? ($up & S_IXGRP ? q{s} : q{S}) :
                           ($up & S_IXGRP ? q{x} : q{-})),
            ($up & S_IROTH ? q{r} : q{-}),
            ($up & S_IWOTH ? q{w} : q{-}),
            ($up & S_ISVTX ? ($up & S_IXOTH ? q{t} : q{T}) :
                           ($up & S_IXOTH ? q{x} : q{-})),
            ($ent->{FileIsDir} == 1 ? $ent->{OffspringCount} + 2 : 1),
            $user || $uid, $group || $gid,
            ($ent->{FileIsDir} == 1 ? 0 : $ent->{$DForkLenKey}),
            strftime($tfmt, localtime $fmodtime),
            $ent->{$pathkey};
        if (S_ISLNK($up)) {
            # Read link path and print that out too...
            my ($rc, %resp) = $session->FPOpenFork(
                    VolumeID    => $vol,
                    DirectoryID => $ent->{ParentDirID},
                    AccessMode  => $kFPAccessReadOnly,
                    PathType    => $pathType,
                    Pathname    => $ent->{$pathkey});
            if ($rc == $kFPNoErr) {
                my $data;
                ($rc, $data) = &{$ReadFn}($session,
                        OForkRefNum => $resp{OForkRefNum},
                        Offset      => 0,
                        ReqCount    => 1024);
                $rc = $session->FPCloseFork($resp{OForkRefNum});
                print q{ -> }, ${$data};
            }
        }
        print qq{\n};
        if ($client_uuid) {
            my($rc, %acl_info) = $session->FPGetACL(
                    VolumeID    => $vol,
                    DirectoryID => $ent->{ParentDirID},
                    PathType    => $pathType,
                    Pathname    => $ent->{$pathkey});
            if ($rc == $kFPNoErr && ($acl_info{Bitmap} & $kFileSec_ACL)) {
                foreach my $i (0 .. $#{$acl_info{acl_ace}}) {
                    my $entry = $acl_info{acl_ace}[$i];
                    my $name;
                    my @args = ();
                    $rc = $session->FPMapID($kUserUUIDToUTF8Name,
                            $entry->{ace_applicable}, \$name);
                    my $idtype;
                    if ($name->{Bitmap} == $kFileSec_UUID) {
                        $idtype = q{user};
                    }
                    elsif ($name->{Bitmap} == $kFileSec_GRPUUID) {
                        $idtype = q{group};
                    }

                    my $acl_kind = $entry->{ace_flags} & $KAUTH_ACE_KINDMASK;
                    my $kind = q{unknown};
                    if ($acl_kind == $KAUTH_ACE_PERMIT) {
                        $kind = q{allow};
                    }
                    elsif ($acl_kind == $KAUTH_ACE_DENY) {
                        $kind = q{deny};
                    }

                    my @actions = ();
                    my $rights = $entry->{ace_rights};
                    if ($rights & $KAUTH_VNODE_READ_DATA) {
                        push @actions, $ent->{FileIsDir} ? q{list} : q{read};
                    }
                    if ($rights & $KAUTH_VNODE_WRITE_DATA) {
                        push @actions, $ent->{FileIsDir} ? q{add_file} :
                                q{write};
                    }
                    if ($rights & $KAUTH_VNODE_EXECUTE) {
                        push @actions, $ent->{FileIsDir} ? q{search} :
                                q{execute};
                    }
                    if ($rights & $KAUTH_VNODE_DELETE) {
                        push @actions, q{delete};
                    }
                    if ($rights & $KAUTH_VNODE_APPEND_DATA) {
                        push @actions, $ent->{FileIsDir} ?
                                q{add_subdirectory} : q{append};
                    }
                    if ($rights & $KAUTH_VNODE_DELETE_CHILD) {
                        push @actions, q{delete_child};
                    }
                    if ($rights & $KAUTH_VNODE_READ_ATTRIBUTES) {
                        push @actions, q{readattr};
                    }
                    if ($rights & $KAUTH_VNODE_WRITE_ATTRIBUTES) {
                        push @actions, q{writeattr};
                    }
                    if ($rights & $KAUTH_VNODE_READ_EXTATTRIBUTES) {
                        push @actions, q{readextattr};
                    }
                    if ($rights & $KAUTH_VNODE_WRITE_EXTATTRIBUTES) {
                        push @actions, q{writeextattr};
                    }
                    if ($rights & $KAUTH_VNODE_READ_SECURITY) {
                        push @actions, q{readsecurity};
                    }
                    if ($rights & $KAUTH_VNODE_WRITE_SECURITY) {
                        push @actions, q{writesecurity};
                    }
                    if ($rights & $KAUTH_VNODE_CHANGE_OWNER) {
                        push @actions, q{chown};
                    }

                    printf qq{ %d: %s:%s %s %s\n}, $i, $idtype,
                            $name->{UTF8Name}, $kind, join q{,}, @actions;
                }
            }
        }
    }
    return;
}

sub expand_globbed_path {
    my ($sess, $volid, $dirid, $path) = @_;

    my $dirBmp = $kFPNodeIDBit | $kFPParentDirIDBit | $pathFlag;
    my $fileBmp = $dirBmp;
    my $fileName = undef;
    my @pathElements = split m{/}sm, $path;
    my $curNode = $dirid;

    my @nameParts;

    if (!defined($pathElements[0]) || ($pathElements[0] eq q{})) {
        $curNode = 2;
        shift @pathElements;
    }
    else {
        my $searchID = $curNode;
        while ($searchID != $topDirID) {
            my $dirbits = $kFPParentDirIDBit | $pathFlag;
            my($rc, $entry) = $sess->FPGetFileDirParms(
                    VolumeID        => $volID,
                    DirectoryID     => $searchID,
                    DirectoryBitmap => $dirbits,
                    PathType        => $pathType,
                    Pathname        => q{});
            unshift @nameParts, $entry->{$pathkey};
            $searchID = $entry->{ParentDirID};
        }
    }
    my @expanded_paths = ( [ $curNode, q{}, @nameParts ] );
    my $pathElem = shift @pathElements;
    while (defined $pathElem) {
        my (@newpaths);
        if ($pathElem eq q{} or $pathElem eq q{.}) {
            $pathElem = shift @pathElements;
            next;
        }
        if ($pathElem eq q{..}) {
            # use unique keyspace temporarily for duplicate checking, since
            # I think this is really the only point where it's a serious
            # concern (so far).
            my %dupchk;
            foreach my $expath (@expanded_paths) {
                next if $expath->[1] ne q{};
                my($rc, $resp) = $sess->FPGetFileDirParms(
                        VolumeID        => $volid,
                        DirectoryID     => $expath->[0],
                        DirectoryBitmap => $kFPParentDirIDBit,
                        PathType        => $pathType,
                        Pathname        => q{});
                next if $rc != $kFPNoErr;
                next if exists $dupchk{$resp->{ParentDirID}};
                push @newpaths, [ $resp->{ParentDirID}, q{},
                        @{$expath}[3 .. $#{$expath}] ];
                $dupchk{$resp->{ParentDirID}} = 1;
            }
            @expanded_paths = @newpaths;
            $pathElem = shift @pathElements;
            next;
        }
        $pathElem =~ tr/:/\//;
        foreach my $expath (@expanded_paths) {
            my ($rc, $resp, %entries);
            $rc = $kFPNoErr;
            my $lastelem;
COLLECT_PATHS:
            while ($rc == $kFPNoErr){
                ($rc, $resp) = &{$EnumFn}($sess,
                               VolumeID         => $volid,
                               DirectoryID      => $expath->[0],
                               FileBitmap       => $fileBmp,
                               DirectoryBitmap  => $dirBmp,
                               ReqCount         => 256,
                               StartIndex       => scalar(keys %entries) + 1,
                               MaxReplySize     => $MaxReplySize,
                               PathType         => $pathType,
                               Pathname         => $expath->[1]);
                if ($rc == $kFPNoErr || $rc == $kFPObjectNotFound) {
                    if ($#{$resp} == 0 && $lastelem &&
                            $resp->[0]->{$pathkey} eq $lastelem) {
                        last COLLECT_PATHS;
                    }
                    foreach my $elem (@{$resp}) {
                        $entries{$elem->{$pathkey}} = $elem;
                    }
                    if ($#{$resp} > -1) {
                        $lastelem = $resp->[-1]{$pathkey};
                    }
                }
            }
            my @matches = sort {$a cmp $b} match_glob($pathElem,
                    keys %entries);
            foreach my $match (@matches) {
                $match =~ tr/\//:/;
                my $nelem = [];
                if ($entries{$match}{FileIsDir}) {
                    @{$nelem} = ($entries{$match}{NodeID}, q{}, $match,
                            @{$expath}[2 .. $#{$expath}],);
                }
                else {
                    @{$nelem} = ($expath->[0], $match,
                            @{$expath}[2 .. $#{$expath}],);
                }
                push @newpaths, $nelem;
            }
        }
        @expanded_paths = @newpaths;

        $pathElem = shift @pathElements;
    }

    return [ @expanded_paths ];
}

# $lastIfDir - the last element can be a directory; needed for removing
# directories, like for FPRemove
# $lastNoExist - the last element might not exist, like for FPCreateFile (i.e.,
# for use as part of the "put" command)
sub resolve_path {
    my ($sess, $volid, $dirid, $path, $lastIfDir, $lastNoExist) = @_;

    if (not defined $lastIfDir) {
        $lastIfDir = 0;
    }
    if (not defined $lastNoExist) {
        $lastNoExist = 0;
    }

    my $dirBmp = $kFPNodeIDBit | $kFPParentDirIDBit;
    my $fileBmp = 0;
    my $fileName = undef;

    my @pathElements = split m{/}sm, $path;
    my $curNode = $dirid;
    if (!defined($pathElements[0]) || ($pathElements[0] eq q{})) {
        $curNode = 2;
        shift @pathElements;
    }
    foreach my $i (0 .. $#pathElements) {
        my $elem = $pathElements[$i];
        my $getParentID = 0;
        next if $elem eq q{.} or $elem eq q{};
        if ($elem eq q{..}) {
            next if $curNode == 2;
            $elem = q{};
            $getParentID = 1;
        }
        $elem =~ tr/:/\//;
        my($rc, $resp) = $sess->FPGetFileDirParms(
                VolumeID        => $volid,
                DirectoryID     => $curNode,
                FileBitmap      => $fileBmp,
                DirectoryBitmap => $dirBmp,
                PathType        => $pathType,
                Pathname        => $elem);
        if (($lastNoExist == 1 and $rc == $kFPObjectNotFound) or
                ($rc == $kFPNoErr and $resp->{FileIsDir} != 1)) {
            if ($i == $#pathElements) {
                $fileName = $elem;
                last;
            }
            else {
                return(undef);
            }
        }
        return(undef) if $rc != $kFPNoErr;
        $curNode = ($getParentID == 1 ? $resp->{ParentDirID} :
                $resp->{NodeID});
    }
    return $curNode, $fileName;
}

if (defined $DT_ID) {
    $session->FPCloseDT($DT_ID);
}
$session->FPCloseVol($volID);
$session->FPLogout();
$session->close();
exit 0;


# vim: ts=4 et ai sw=4 hls
