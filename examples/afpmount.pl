#!/usr/bin/env perl

use Net::AFP::Fuse;
use IO::Poll qw(POLLIN POLLERR);
use Getopt::Long;				# for parsing command line options
use Socket;

# Conditionally include Term::ReadPassword; it doesn't need to be present
# for supplying passwords via the AFP URL directly, but it's needed for
# prompting.
my $has_Term_ReadPassword = 1;
eval { require Term::ReadPassword; };
if ($@) { $has_Term_ReadPassword = 0; }

# define constants {{{1
use constant MSG_NEEDPASSWORD	=> 1;
use constant MSG_PASSWORDIS		=> 2;
use constant MSG_RUNNING		=> 3;
use constant MSG_STARTERR		=> 4;
use constant MSGFORMAT			=> 'CS';
use constant MSGLEN				=> 3;
my @msgfields = ('msg', 'payloadlen');
# }}}1

# Handle the command line args.
my $interactive;
exit(&EINVAL) unless GetOptions('interactive'	=> \$interactive);

my($path, $mountpoint) = @ARGV;

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

    my $poll = new IO::Poll;
    $poll->mask(\*CHILD, POLLIN | POLLERR);
	while (1) {
        $poll->poll(1);
		if ($poll->events(\*CHILD) & POLLIN) {
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
                my ($username, $hostname) = unpack('S/a*S/a*', $payload);
				my $prompt = 'Password for ' . $username .
						' at ' . $hostname . ': ';
				my $pw ;
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
		if ($poll->events(\*CHILD) & POLLERR) {
			# this should never happen...
			print "unknown socket failure occurred, aborting\n";
			exit(1);
		}
	}

	# this should never happen...
	exit(1);
} # }}}1
close(CHILD);

my $fuse;

# Hook the tail of the execution path to close the connection properly, rather
# than having to do it again and again.
# hook program exit {{{1
sub END {
   $fuse->disconnect() if ref($fuse);
} # }}}1

$fuse = new Net::AFP::Fuse($path, sub {
        my ($username, $hostname, $password) = @_;
		if (!defined $password && defined $interactive) {
            my $sp = pack('S/a*S/a*', $username, $hostname);
			syswrite(PARENT, pack(MSGFORMAT, MSG_NEEDPASSWORD, length($sp)) .
                    $sp);
			my ($data, $payload, %msg) = ('', '');
            my $poll = new IO::Poll;
            $poll->mask(\*PARENT, POLLIN);
            $poll->poll(1);
			sysread(PARENT, $data, MSGLEN);
			@msg{@msgfields} = unpack(MSGFORMAT, $data);
			if ($msg{'payloadlen'} > 0) {
				sysread(PARENT, $payload, $msg{'payloadlen'});
			}
			$password = $payload;
		}
		unless (defined $password) {
			$password = '';
		}
    	return $password;
    });

unless (ref($fuse)) {
    # if this happens, an error code was returned, so pass that back to
    # the parent process...
    syswrite(PARENT, pack(MSGFORMAT . 's', MSG_STARTERR, 2, $fuse));
    exit(1);
}


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

my $script_name = $0;
$0 = join(' ', $script_name, $path, $mountpoint);

$fuse->main( 'mountpoint'	=> $mountpoint,
			 'mountopts'	=> 'allow_other,fsname=' . $path );

# If we reach this point, the FUSE mountpoint has been released, so exit
# quietly...
exit(0);

# vim: ts=4 fdm=marker sw=4 et
