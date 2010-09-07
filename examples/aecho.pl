#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use IO::Socket::DDP;
use Net::Atalk;
use Net::Atalk::NBP;
use Time::HiRes qw(gettimeofday setitimer ITIMER_REAL);
use Errno qw(EINTR);
use Getopt::Long;
use constant AEPOP_REQUEST	=> 1;
use constant AEPOP_REPLY	=> 2;

use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

my $port = getservbyname('echo', 'ddp') || 4;

my ($msec_total, $msec_min, $msec_max, $sent, $rcvd, $dups) =
		(0, -1, -1, 0, 0, 0);
my $count = 0;
my %sockparms = ('Proto' => 'ddp');

GetOptions( 'c=i'	=> \$count,
		    'A=s'	=> sub { $sockparms{'LocalAddr'} = $_[1] },
			'b'		=> sub { $sockparms{'Broadcast'} = 1 } ) || usage();

usage() unless scalar(@ARGV) == 1;
my ($target) = @ARGV;

my $paddr = atalk_aton($target);
unless (defined $paddr) {
	$target =~ s/(?::([\w\s\-]*|=))?(?:\@(\w*|\*))?$//;
	my ($type, $zone) = ($1, $2);
	my @tuples = NBPLookup($target, $type, $zone, exists $sockparms{'LocalAddr'} ? $sockparms{'LocalAddr'} : undef, 1);
	unless (scalar(@tuples)) {
		printf(STDERR "Can't resolve \"\%s\"\n", $target);
		exit(1);
	}
	$target = $tuples[0][0];
	$paddr = atalk_aton($target);
}
my $sock = new IO::Socket::DDP(%sockparms) or die "Can't bind: $@";
my $dest = pack_sockaddr_at($port, $paddr);

sub usage {
	print "usage:\t", $0, " [-A source address ] [-c count] [-b] ( addr | nbpname )\n";
	exit(1);
}

sub send_echo {
	# Have to save $!, because we happily stomp all over it with our crap.
	my $orig_err = $!;
	my $msg = pack('CCLLL', DDPTYPE_AEP, AEPOP_REQUEST, $sent++,
			gettimeofday());
	die "send() failed: $!" unless defined send($sock, $msg, 0, $dest);
	if ($count && $sent > $count) { finish() }
	$SIG{'ALRM'} = \&send_echo;
	# And restore $! before we go...
	$! = $orig_err;
}

sub finish {
	if ($sent) {
		printf("\n---- \%s AEP Statistics ----\n", $target);
		printf("\%d packets sent, \%d packets received\%s, \%d\%\% packet loss\n",
			 $sent, $rcvd, $dups ? sprintf(', +%u duplicates', $dups) : '',
			 ($sent - $rcvd) * 100 / $sent);
		if ($rcvd) {
			printf("round trip (msec) min/avg/max: \%.3f/\%.3f/\%.3f\n",
				$msec_min, $msec_total / ($rcvd + $dups), $msec_max);
		}
	}
	exit(0);
}

$SIG{'INT'} = \&finish;
$SIG{'ALRM'} = \&send_echo;

setitimer(ITIMER_REAL, 1.0, 1.0);

while (1) {
	my $rbuf;
	my $from = recv($sock, $rbuf, DDP_MAXSZ, 0);
	unless (defined $from) {
		next if $! == EINTR;
		die "recv failed: $!";
	}
	if ($rcvd < $sent) { $rcvd++ } else { $dups++ }
	my ($now_sec, $now_usec) = gettimeofday();
	my ($ddptype, $aeptype, $seqno, $t_sec, $t_usec) =
		 unpack('CCLLL', $rbuf);
	my $delta = ($now_sec - $t_sec) * 1000 + ($now_usec - $t_usec) / 1000;
	$msec_total += $delta;
	if ($delta > $msec_max) { $msec_max = $delta }
	if ($delta < $msec_min || $msec_min == -1) { $msec_min = $delta }
	my $haddr = atalk_ntoa( (unpack_sockaddr_at($from))[1] );
	printf("\%d bytes from \%s: aep_seq=\%d, \%.3f msec\n", length($rbuf),
			$haddr, $seqno, $delta);
	if ($count && $seqno + 1 >= $count) { finish() }
}

# vim: ts=4
