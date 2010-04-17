package Net::Atalk::NBP;

use IO::Socket::DDP;
use Net::Atalk;
use IO::Poll qw(POLLIN);
use Time::HiRes;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT = qw(NBP_BrRq NBP_LkUp NBP_LkUp_Reply NBP_FwdReq);

use constant NBP_BrRq		=> 1;
use constant NBP_LkUp		=> 2;
use constant NBP_LkUp_Reply	=> 3;
use constant NBP_FwdReq		=> 4;

my $id = 1;

sub AssemblePacket {
	my ($Function, $ID, @Tuples) = @_;

	die("Can't have more than 15 tuples") if scalar(@Tuples) > 15;
	return(pack('CCC', DDPTYPE_NBP, (($Function & 0x0f) << 4) | scalar(@Tuples),
				$ID) . join('', map { AssembleTuple(@{$_}) } @Tuples));
}

sub AssembleTuple {
	my ($NodeAddr, $SockNo, $Enumerator, $Object, $Type, $Zone) = @_;

	return pack('a[3]CCC/aC/aC/a', atalk_aton($NodeAddr), $SockNo,
			$Enumerator, $Object, $Type, $Zone);
}

sub UnpackPacket {
	my ($packet) = @_;

	my ($pkttype, $fn_cnt, $ID, $tupledata) = unpack('CCCa*', $packet);
	die() unless $pkttype == DDPTYPE_NBP;
	my $Function = ($fn_cnt >> 4) & 0x0F;
	my $tuplecount = $fn_cnt & 0x0F;
	return($Function, $ID, UnpackTuples($tuplecount, $tupledata));
}

sub UnpackTuples {
	my ($tuplecount, $tupledata) = @_;
	
	my @tuple_data = unpack('a[3]CCC/aC/aC/a' x $tuplecount, $tupledata);
	my @tuples;
	for (my $i = 0; $i < $tuplecount; $i++) {
		my @tuple = @tuple_data[ ($i * 6) .. (($i * 6) + 5) ];
		$tuple[0] = atalk_ntoa($tuple[0]);
		push(@tuples, [ @tuple ]);
	}
	return(@tuples);
}

sub Lookup {
	my($Obj, $Type, $Zone, $FromAddr, $maxresps) = @_;

	# Bind a local, broadcast-capable socket for sending out NBP
	# packets from (and receiving responses).
	my %sockparms = ( 'Proto'		=> 'ddp',
					  'Broadcast'	=> 1 );
	if (defined $FromAddr) { $sockparms{'LocalAddr'} = $FromAddr }
	my $sock = new IO::Socket::DDP(%sockparms) || die $!;

	# If the lookup properties are undef, assume wildcards were intended.
	unless (defined $Obj) { $Obj = '=' }
	unless (defined $Type) { $Type = '=' }
	unless (defined $Zone) { $Zone = '*' }

	# Construct a lookup packet with a single tuple, requesting the given
	# entity name, service type and zone.
	my $packet = AssemblePacket(NBP_LkUp, $id++,
			[ $sock->sockhost(), $sock->sockport(), 0, $Obj, $Type, $Zone ]);

	# Try to look up the DDP port number for NBP; use the default if we
	# can't.
	my $port = getservbyname('nbp', 'ddp') || 2;

	# Pack a sockaddr_at for the broadcast address with the port number we
	# get above.
	my $dest = pack_sockaddr_at($port, atalk_aton('0.255'));

	my %rset;
	my @records;
RETRY:
	for (my $tries = 3; $tries > 0; $tries--) {
		# Send the query packet to the global broadcast address.
		send($sock, $packet, 0, $dest);

		my $poll = new IO::Poll();
		$poll->mask($sock, POLLIN);

		my $timeout = 2.0;
		while (1) {
			my ($s_sec, $s_usec) = gettimeofday();
			next RETRY unless $poll->poll($timeout);
			my ($e_sec, $e_usec) = gettimeofday();
			$timeout -= ($e_sec - $s_sec) + (($e_usec - $s_usec) / 1000000);

			my $rbuf;
			return unless defined recv($sock, $rbuf, DDP_MAXSZ, 0);

			my ($fn, $r_id, @tuples) = UnpackPacket($rbuf);

			next unless $fn == NBP_LkUp_Reply;

			foreach my $tuple (@tuples) {
				my $key = join('|', @$tuple[3,4]);
				next if exists $rset{$key};
				last RETRY if scalar(keys %rset) >= $maxresps;
				$rset{$key} = $tuple;
				push(@records, $tuple);
			}
		}
	}

	return(@records);
}

1;
