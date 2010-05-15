package Net::Atalk::NBP;

use IO::Socket::DDP;
use Net::Atalk;
use IO::Poll qw(POLLIN);
use Time::HiRes qw(gettimeofday);

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT = qw(NBP_BrRq NBP_FwdReq NBPLookup);

=head1 NAME

Net::Atalk::NBP - AppleTalk Name Binding Protocol operations

=head1 SYNOPSIS

    use Net::Atalk::NBP;

=head1 DESCRIPTION

C<Net::Atalk::NBP> provides (currently) one function for resolving NBP
(Name Binding Protocol) host, zone and service name groups into
AppleTalk host addresses and ports.

=over

=cut

use constant NBP_BrRq		=> 1;
use constant NBP_LkUp		=> 2;
use constant NBP_LkUp_Reply	=> 3;
use constant NBP_FwdReq		=> 4;

our $id = 1;

# Construct an NBP packet.
sub AssemblePacket {
	my ($Function, $ID, @Tuples) = @_;

	die("Can't have more than 15 tuples") if scalar(@Tuples) > 15;
	return(pack('CCC', DDPTYPE_NBP, (($Function & 0x0f) << 4) | scalar(@Tuples),
				$ID) . join('', map { AssembleTuple(@{$_}) } @Tuples));
}

# Construct an NBP singleton tuple.
sub AssembleTuple {
	my ($NodeAddr, $SockNo, $Enumerator, $Object, $Type, $Zone) = @_;

	return pack('a[3]CCC/aC/aC/a', atalk_aton($NodeAddr), $SockNo,
			$Enumerator, $Object, $Type, $Zone);
}

# Unpack an NBP packet into its constituent fields.
sub UnpackPacket {
	my ($packet) = @_;

	my ($pkttype, $fn_cnt, $ID, $tupledata) = unpack('CCCa*', $packet);
	return unless $pkttype == DDPTYPE_NBP;
	my $Function = ($fn_cnt >> 4) & 0x0F;
	my $tuplecount = $fn_cnt & 0x0F;
	return($Function, $ID, UnpackTuples($tuplecount, $tupledata));
}

# Unpack a packed set of NBP record tuples.
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

=item NBPLookup (OBJ, TYPE, ZONE, FROMADDR, MAXRESPS)

Implements NBP Lookup request issuing and fetching. All arguments are
optional. Object name, type (service name) and AppleTalk zone can be
specified, and will be included in the request if given. An explicit
source address can be specified, as well as a maximum number of
tuples to fetch as part of the request.

=cut
sub NBPLookup {
	my($Obj, $Type, $Zone, $FromAddr, $maxresps) = @_;

	# Bind a local, broadcast-capable socket for sending out NBP
	# packets from (and receiving responses).
	my %sockparms = ( 'Proto'		=> 'ddp',
					  'Broadcast'	=> 1 );
	if (defined $FromAddr) { $sockparms{'LocalAddr'} = $FromAddr }
	my $sock = new IO::Socket::DDP(%sockparms) || die $!;
	die("Can't get local socket address, possibly atalk stack out of order")
			unless defined $sock->sockhost();

	# If the lookup properties are undef (or empty strings), assume
	# wildcards were intended.
	unless (defined $Obj && $Obj ne '') { $Obj = '=' }
	unless (defined $Type && $Type ne '') { $Type = '=' }
	unless (defined $Zone && $Zone ne '') { $Zone = '*' }

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

		# Set up a poll() object to check the socket for incoming packets.
		my $poll = new IO::Poll();
		$poll->mask($sock, POLLIN);

		my $timeout = 2.0;
		while (1) {
			my ($s_sec, $s_usec) = gettimeofday();
			# Poll the socket for traffic, and retry the whole damn thing
			# if we don't see anything at all.
			next RETRY unless $poll->poll($timeout);
			my ($e_sec, $e_usec) = gettimeofday();
			# Compute how long it took us to poll the socket.
			$timeout -= ($e_sec - $s_sec) + (($e_usec - $s_usec) / 1000000);

			# Read in the packet on the socket.
			my $rbuf;
			return unless defined recv($sock, $rbuf, DDP_MAXSZ, 0);

			# Unpack the NBP packet.
			my ($fn, $r_id, @tuples) = UnpackPacket($rbuf);

			# If the packet wasn't a lookup-reply packet (or an NBP packet,
			# if $fn is undef), just ignore it.
			next unless defined $fn and $fn == NBP_LkUp_Reply;

			# Do some duplicate checking, then add the tuples to the set
			# to be returned to the caller.
			foreach my $tuple (@tuples) {
				my $key = join('|', @$tuple[3,4]);
				next if exists $rset{$key};
				$rset{$key} = $tuple;
				push(@records, $tuple);
				last RETRY if $maxresps and scalar(@records) >= $maxresps;
			}
		}
	}

	return(@records);
}
=back

=head1 REFERENCES

The Name Binding Protocol implementation contained herein is based on the
protocol description as provided by Apple, in the book "Inside AppleTalk",
chapter 7. "Inside AppleTalk" is available freely via the Internet in
PDF form, at:

L<http://developer.apple.com/MacOs/opentransport/docs/dev/Inside_AppleTalk.pdf>

Also, netatalk's libatalk and nbplkup tool were used as source references
for development (see L<http://netatalk.sourceforge.net/>).

=head1 SEE ALSO

L<Net::Atalk>, L<IO::Socket::DDP>

=cut
1;
