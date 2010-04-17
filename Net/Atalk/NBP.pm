use IO::Socket::DDP;
use Net::Atalk;

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
	my($Obj, $Type, $Zone, $FromAddr) = @_;

	my $sock = new IO::Socket::DDP( 'Proto'		=> 'ddp',
									'Broadcast'	=> 1 ) || die $!;
	my $packet = AssemblePacket(NBP_LkUp, $id++,
			[ $sock->sockhost(), $sock->sockport(), 0, $Obj, $Type, $Zone ]);
	my $dest = pack_sockaddr_at($port, atalk_aton('0.255'));
	send($sock, $packet, 0, $dest);

}

1;
