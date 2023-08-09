#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

# Enables a nice call trace on warning events.
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

use Fuse::AFP;
use Net::AFP;                       # just for its $VERSION...
use Net::AFP::Result;
use Net::AFP::Helpers;
use IO::Poll qw(POLLIN POLLERR);
use Getopt::Long;                   # for parsing command line options
use Socket;
use Errno qw(:POSIX);
use URI::Escape;
use English qw(-no_match_vars);
use Readonly;
use Log::Log4perl;

# Do conditional includes of several modules, and denote to ourselves
# if they got imported or not.
# conditional includes {{{1
my $has_Term__ReadPassword = 0;
eval {
    require Term::ReadPassword;
    1;
} and do {
    Term::ReadPassword->import;
    $has_Term__ReadPassword = 1;
};

my $has_Net__Bonjour = 0;
eval {
    require Net::Bonjour;
    1;
} and do {
    Net::Bonjour->import;
    $has_Net__Bonjour = 1;
};

my $has_atalk = 0;
eval {
    require Net::AFP::Atalk;    # The class to connect to an AppleTalk server
                                # via AppleTalk protocol.
    require Net::Atalk::NBP;
    1;
} and do {
    $has_atalk = 1;
    Net::Atalk::NBP->import;
};

# }}}1

# define constants {{{1
Readonly our $MSG_NEEDPASSWORD  => 1;
Readonly our $MSG_PASSWORDIS    => 2;
Readonly our $MSG_RUNNING       => 3;
Readonly our $MSG_STARTERR      => 4;
Readonly our $MSGFORMAT         => 'CS';
Readonly our $MSGLEN            => 3;
my @msgfields = qw(msg payloadlen);
# }}}1

sub usage { #{{{1
    print <<"_EOT_";

afp-perl version ${Net::AFP::VERSION} - Apple Filing Protocol mount tool

Usage: ${PROGRAM_NAME} [options] [AFP URL] [mount point]

Options:
    -i|--interactive
        Mount interactively; if a password is required, prompt for it.
    -o|--options [options]
        Pass mount options, comma separated, like mount(8).
    -h|--help
        This help summary.
    -4|--prefer-v4
        Use IPv4 connectivity before IPv6, if available.
    --atalk-first
        Use AppleTalk transport before IP transport, if available; normally
        IP transport is used first, for performance reasons.
    --list-servers
        Query for AFP servers via mDNS if Net::Bonjour is available,
        and via NBP if Net::Atalk is available.
    --list-mounts [AFP URL]
        Query the given AFP server, using supplied credentials if given,
        for the mounts available. Prompts for password if username is
        given, but no password.

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
    exit EINVAL;
} #}}}1

sub list_mounts { #{{{1
    my($callback, $url) = @_;
    # See if there's a URL on @ARGV with at least a hostname (and possibly
    # user creds), and try to get a mount list from the server.

    my $pw_cb =  sub {
        my(%values) = @_;
        my $prompt = 'Password for ' . $values{username} .
                ' at ' . $values{host} . ': ';
        return $values{password} if $values{password};
        return read_password($prompt) if $has_Term__ReadPassword;
        return q{};
    };

    my $session = do_afp_connect($pw_cb, $url, undef);
    if (!ref($session) || !$session->isa('Net::AFP')) {
        exit $session;
    }

    my $srvrParms;
    $session->FPGetSrvrParms(\$srvrParms);
    print map { $_->{VolName} ."\n" } @{$srvrParms->{Volumes}};

    $session->FPLogout();
    $session->close();
    exit 0;
} #}}}1

sub list_servers { #{{{1
    # Try to use Bonjour (and NBP, if it's available?) to get a list of
    # available AFP servers that one *could* mount shares from...

    my @servers;
    if (!$has_Net__Bonjour && !$has_atalk) {
        print {\*STDERR} <<'_EOT_';
Neither Net::Bonjour nor Net::Atalk::NBP was available; can't discover
servers without at least one of these present!
_EOT_
        exit EOPNOTSUPP;
    }

    if ($has_Net__Bonjour) {
        my $discover = new Net::Bonjour('afpovertcp', 'tcp');
        $discover->discover();

        push(@servers, map { q{afp://} . uri_escape($_->hostname()) . q{/} }
                $discover->entries());
    }

    if ($has_atalk) {
        my @NBPResults;

        eval {
            # Call this in an eval block so that if the AFP stack isn't
            # functional, when it calls die() the whole thing doesn't
            # fall apart on us.
            @NBPResults = NBPLookup(undef, 'AFPServer');
        } or carp('AppleTalk stack is probably broken');

        push @servers, map { q{afp:/at/} . uri_escape($_->[3]) . q{/} }
                @NBPResults;
    }

    print map { $_ . "\n" } @servers;

    exit 0;
} #}}}1

# Handle the command line args. {{{1
my($interactive, $options, $prefer_v4, $atalk_first, $debug_afp, $debug_dsi, $debug_fuse);
# For now accept --options/-o, and just don't do anything with the option
# string we get, that allows mounting via fstab to work.
GetOptions('interactive'    => \$interactive,
           'options=s'      => \$options,
           'help'           => \&usage,
           'list-mounts=s'  => \&list_mounts,
           'list-servers'   => \&list_servers,
           '4|prefer-v4'    => \$prefer_v4,
           'atalk-first'    => \$atalk_first,
           'debug-afp'      => \$debug_afp,
           'debug-dsi'      => \$debug_dsi,
           'debug-fuse'     => \$debug_fuse) || exit EINVAL;

my $logconf = <<'_EOT_';
log4perl.appender.Syslog = Log::Dispatch::Syslog
log4perl.appender.Syslog.Facility = user
log4perl.appender.Syslog.layout = PatternLayout
log4perl.appender.Syslog.layout.ConversionPattern = [%P] %F line: %L %c - %m%n

log4perl.appender.Console = Log::Log4perl::Appender::Screen
log4perl.appender.Console.layout = SimpleLayout
log4perl.appender.Syslog.Threshold = INFO

log4perl.logger = INFO, Syslog
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

if (defined $debug_fuse) {
    $logconf .= <<'_EOT_';
log4perl.logger.Fuse.AFP = DEBUG, Console
_EOT_
}
Log::Log4perl->init(\$logconf);

my($path, $mountpoint) = @ARGV;

if (!$path || !$mountpoint) {
    usage();
}

if (!-d $mountpoint) {
    print {\*STDERR} "ERROR: attempted to mount to non-directory\n";
    exit ENOTDIR;
}#}}}1

my %options;
if ($options) {
    foreach my $pair (split m{,}s, $options) {
        my ($key, $val) = split m{=}s, $pair;
        $options{$key} = $val;
    }
}

# Set up address family order {{{1
my @aforder = ( AF_INET );
if ($prefer_v4) {
    push @aforder, AF_INET6;
}
else {
    unshift @aforder, AF_INET6;
}
if ($atalk_first) {
    unshift @aforder, AF_APPLETALK;
}
else {
    push @aforder, AF_APPLETALK;
} #}}}1

# make the parent process into a really simple rpc server that handles
# messages from the actual client process (which will go into the
# background), for things like getting the user's password.
# parent IPC {{{1
socketpair CHILD, PARENT, AF_UNIX, SOCK_STREAM, PF_UNSPEC
        or croak('socketpair() failed: ' . $ERRNO);
my $pid = fork;
croak('fork() failed: ' . $ERRNO) if not defined $pid;
if ($pid > 0) {
    # parent process; we want the child to become independent, but first we
    # have to hang around until it's running happily.
    close(PARENT) || carp('Couldn\'t close socket to parent process');

    my $poll = new IO::Poll;
    $poll->mask(\*CHILD, POLLIN | POLLERR);
    while (1) {
        $poll->poll(1);
        if ($poll->events(\*CHILD) & POLLIN) {
            # process received message {{{2
            my $data = q{};
            my $len = sysread CHILD, $data, $MSGLEN;
            last unless $len;
            my %msg;
            @msg{@msgfields} = unpack $MSGFORMAT, $data;
            my $payload;
            if ($msg{payloadlen}) {
                sysread CHILD, $payload, $msg{payloadlen};
            }

            if ($msg{msg} == $MSG_RUNNING) {
                # the child process has said everything's happy, so we can
                # now go away; it could still implode, but it's now to a
                # point where we can't do anything about it.
                exit 0;
            }
            elsif ($msg{msg} == $MSG_STARTERR) {
                # some sort of failure condition occurred.
                my $failcode = unpack 's', $payload;
                exit $failcode;
            }
            elsif ($msg{msg} == $MSG_NEEDPASSWORD) {
                # child process needs a password, so we'll do the prompting
                # for it.
                my ($username, $hostname) = unpack 'S/a*S/a*', $payload;
                my $prompt = 'Password for ' . $username .
                        ' at ' . $hostname . ': ';
                my $pw;
                if ($has_Term__ReadPassword) {
                    $pw = read_password($prompt);
                }
                else {
                    print 'Term::ReadPassword was not available, can\'t ',
                            "get password\n";
                }
                syswrite CHILD, pack($MSGFORMAT, $MSG_PASSWORDIS,
                        length $pw) . $pw;
            }
            else {
                # this should never happen...
                print "unknown message received?\n";
                exit 1;
            } # }}}2
        }
        if ($poll->events(\*CHILD) & POLLERR) {
            # this should never happen...
            print "unknown socket failure occurred, aborting\n";
            exit 1;
        }
    }

    # this should never happen...
    exit 1;
} # }}}1
close(CHILD) || carp('Couldn\'t close socket to child process');

my $fuse;

# Hook the tail of the execution path to close the connection properly, rather
# than having to do it again and again.
# hook program exit {{{1
sub END {
   $fuse->disconnect() if ref $fuse;
} # }}}1

# instantiate fuse object {{{1
eval {
    $fuse = new Fuse::AFP($path, sub {
            my ($username, $hostname, $password) = @_;
            if (!defined $password && defined $interactive) {
                my $sp = pack 'S/a*S/a*', $username, $hostname;
                syswrite PARENT, pack($MSGFORMAT, $MSG_NEEDPASSWORD,
                            length $sp) . $sp;
                my ($data, $payload, %msg) = (q{}, q{});
                my $poll = new IO::Poll;
                $poll->mask(\*PARENT, POLLIN);
                $poll->poll(1);
                sysread PARENT, $data, $MSGLEN;
                @msg{@msgfields} = unpack $MSGFORMAT, $data;
                if ($msg{payloadlen} > 0) {
                    sysread PARENT, $payload, $msg{payloadlen};
                }
                $password = $payload;
            }
            if (!defined $password) {
                $password = q{};
            }
            return $password;
        }, %options, aforder => [ @aforder ]);
} or do {
    # If an exception does happen, it's probably due to an invalid URL...
    print {\*STDERR} "Error while invoking Fuse::AFP:\n", $EVAL_ERROR;
    syswrite PARENT, pack($MSGFORMAT . 's', $MSG_STARTERR, 2, EINVAL);
    exit 1;
};

if (!ref $fuse) {
    # if this happens, an error code was returned, so pass that back to
    # the parent process...
    syswrite PARENT, pack($MSGFORMAT . 's', $MSG_STARTERR, 2, $fuse);
    exit 1;
} #}}}1

# Send a love note to the folks saying "wish you were here, everything's
# fine".
syswrite PARENT, pack($MSGFORMAT, $MSG_RUNNING, 0);
close(PARENT) || carp('Couldn\'t close socket to parent process');

# reopen the standard FDs onto /dev/null; they have to be open, since if
# anything writes to the default FDs after they get opened to by something
# else, things can break badly.
#open(STDIN, '<', '/dev/null');
#open(STDOUT, '>', '/dev/null');
#open(STDERR, '>&', \*STDOUT);

my $script_name = $PROGRAM_NAME;
local $PROGRAM_NAME = join q{ }, $script_name, $path, $mountpoint;

# Fixed options that we always want passed...
$options{allow_other} = undef;
$options{subtype}     = 'pafpfs';
$options{fsname}      = $path;
delete $options{encoding};
delete $options{novolicon};

my %mainopts;

if (exists $options{debug}) {
    delete $options{debug};
    $mainopts{debug} = 1;
}

$mainopts{mountpoint} = $mountpoint;
$mainopts{mountopts}  = join(q{,}, map { $_ . (defined($options{$_}) ? q{=} . $options{$_} : q{}) } keys %options );

$fuse->main(%mainopts);

# If we reach this point, the FUSE mountpoint has been released, so exit
# quietly...
exit 0;

# vim: ts=4 fdm=marker sw=4 et hls
