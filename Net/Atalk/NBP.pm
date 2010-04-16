use IO::Socket::DDP;

use strict;
use warnings;

use constant NBP_BrRq		=> 1;
use constant NBP_LkUp		=> 2;
use constant NBP_LkUp_Reply	=> 3;
use constant NBP_FwdReq		=> 4;

my $id = 1;

sub AssemblePacket {
	my($Function, $ID, @Tuples) = @_;

	return(pack('CC', (($Function & 0x0f) << 4) & scalar(@Tuples)) .
			join('', map { AssembleTuple(@{$_}) } @Tuples));
}

sub AssembleTuple {
	my($NodeAddr, $SockNo, $Enumerator, $Object, $Type, $Zone) = @_;

	return pack('a[4]CC/aC/aC/a', pack_sockaddr_at($SockNo, $NodeAddr),
			$Enumerator, $Object, $Type, $Zone);
}

sub Lookup {
	my($Obj, $Type, $Zone, $FromAddr) = @_;

	my $packet = AssemblePacket(NBP_LkUp, $id++, [ '0.0', 0, 0, $Obj, $Type, $Zone ]);
	my $sock = new IO::Socket::DDP( 'PeerAddr'	=> '0.0',
									'PeerPort'	=> 'nbp',
									'Proto'		=> AF_APPLETALK );
	send($sock, $packet, 0);
}

1;
