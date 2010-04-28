package Net::Atalk::ZIP;

use IO::Socket::DDP;
use Net::Atalk;
use Net::Atalk::ATP;
use IO::Poll qw(POLLIN);
use Exporter qw(import);

=head1 NAME

Net::Atalk::ZIP - AppleTalk Zone Information Protocol operations

=head1 SYNOPSIS

    use Net::Atalk::ZIP;

=head1 DESCRIPTION

C<Net::Atalk::NBP> provides functions for getting information about
AppleTalk zones, including getting the local zone name, enumerating
zones known to AppleTalk routers, and net number range information
for known zones.

=over

=cut

use constant ZIP_Query_Req			=> 1;
use constant ZIP_Query_Resp			=> 2;
use constant ZIP_Query_RespExt		=> 8;
use constant ZIP_GetNetInfo_Req		=> 5;
use constant ZIP_GetNetInfo_Resp	=> 6;
use constant ZIP_ATP_GetMyZone		=> 7;
use constant ZIP_ATP_GetZoneList	=> 8;
use constant ZIP_ATP_GetLocalZones	=> 9;

use constant ZIP_GNI_ZoneInvalid	=> 0x80;
use constant ZIP_GNI_UseBroadcast	=> 0x40;
use constant ZIP_GNI_OnlyOneZone	=> 0x20;

our @EXPORT = qw(ZIPQuery ZIPGetZoneList ZIPGetLocalZones ZIPGetMyZone
		ZIPGetNetInfo);

=item ZIPQuery (NETNUM, ...)

Requests mapping of AppleTalk network numbers to their corresponding
ZIP zone names. Multiple zones may be resolved in a single lookup.

=cut
sub ZIPQuery {
	my (@netnums) = @_;

	my $port = getservbyname('zip', 'ddp') || 6;
	# Bind a local, broadcast-capable socket for sending out NBP
	# packets from (and receiving responses).
	my %sockparms = ( 'Proto'		=> 'ddp',
					  'Broadcast'	=> 1 );
	my $sock = new IO::Socket::DDP(%sockparms) || die $!;
	die("Can't get local socket address, possibly atalk stack out of order")
			unless defined $sock->sockhost();

	my $dest = pack_sockaddr_at($port, atalk_aton('0.255'));
	my $msg = pack('CCC/n*', DDPTYPE_ZIP, ZIP_Query_Req, @netnums);
	send($sock, $msg, 0, $dest);

	my $zonemap = {};
	my $poll = new IO::Poll();
	$poll->mask($sock, POLLIN);
	return undef unless $poll->poll(2);
	my $rbuf;
	my $from = recv($sock, $rbuf, DDP_MAXSZ, 0);
	return undef unless defined $from;
	my ($ddptype, $ziptype) = unpack('CC', $rbuf);
	return undef unless $ddptype == DDPTYPE_ZIP;
	return undef unless $ziptype == ZIP_Query_Resp ||
			$ziptype == ZIP_Query_RespExt;
	my @data = pack('xxC/(nC/a*)', $rbuf);
	my %namedata;
	while (scalar(@data)) {
		my $zonenum = shift(@data);
		my $zonename = shift(@data);
		unless (exists $namedata{$zonenum}) { $namedata{$zonenum} = [] }
		push(@{$namedata{$zonenum}}, $zonename);
	}

	return { %namedata };
}

sub ZIPGetZoneList {
	my ($ToAddr, $StartIndex) = @_;
	my $conn = new Net::Atalk::ATP();
	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, atalk_aton($ToAddr || '0.0'));

	my $user_bytes = pack('Cxn', ZIP_ATP_GetZoneList, $StartIndex);
	my $rdata;
	my $success;
	my ($txid, $sem) = $conn->SendTransaction(0, $dest, '', $user_bytes, 1,
			\$rdata, 2, 2, 0, \$success);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($LastFlag, $count) = unpack('Cxn', $$rdata[0]{'userbytes'});
		my @zonenames = unpack('C/a*' x $count, $$rdata[0]{'payload'});
		return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
	}
	return undef;
}

sub ZIPGetLocalZones {
	my ($ToAddr, $StartIndex) = @_;
	my $conn = new Net::Atalk::ATP();
	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, atalk_aton($ToAddr || '0.0'));

	my $user_bytes = pack('Cxn', ZIP_ATP_GetLocalZones, $StartIndex);
	my $rdata;
	my $success;
	my ($txid, $sem) = $conn->SendTransaction(0, $dest, '', $user_bytes, 1,
			\$rdata, 2, 2, 0, \$success);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($LastFlag, $count) = unpack('Cxn', $$rdata[0]{'userbytes'});
		my @zonenames = unpack('C/a*' x $count, $$rdata[0]{'payload'});
		return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
	}
	return undef;
}

sub ZIPGetMyZone {
	my ($ToAddr) = @_;
	my $conn = new Net::Atalk::ATP();
	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, atalk_aton($ToAddr || '0.0'));

	my $user_bytes = pack('Cxn', ZIP_ATP_GetMyZone, 0);
	my $rdata;
	my $success;
	my ($txid, $sem) = $conn->SendTransaction(0, $dest, '', $user_bytes, 1,
			\$rdata, 2, 2, 0, \$success);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($count) = unpack('xxn', $$rdata[0]{'userbytes'});
		die() if $count != 1;
		my ($zonename) = unpack('C/a*', $$rdata[0]{'payload'});
		return $zonename;
	}
	return undef;
}

sub ZIPGetNetInfo {
	my ($zonename) = @_;

	my $port = getservbyname('zip', 'ddp') || 6;
	# Bind a local, broadcast-capable socket for sending out NBP
	# packets from (and receiving responses).
	my %sockparms = ( 'Proto'		=> 'ddp',
					  'Broadcast'	=> 1 );
	my $sock = new IO::Socket::DDP(%sockparms) || die $!;
	die("Can't get local socket address, possibly atalk stack out of order")
			unless defined $sock->sockhost();

	my $dest = pack_sockaddr_at($port, atalk_aton('0.255'));
	my $msg = pack('Cx[5]C/a*', DDPTYPE_ZIP, ZIP_GetNetInfo_Req, $zonename);
	send($sock, $msg, 0, $dest);

	my $poll = new IO::Poll();
	$poll->mask($sock, POLLIN);
	return undef unless $poll->poll(2);
	my $rbuf;
	my $from = recv($sock, $rbuf, DDP_MAXSZ, 0);
	return undef unless defined $from;
	my ($ddptype, $ziptype) = unpack('CC', $rbuf);
	return undef unless $ddptype == DDPTYPE_ZIP;
	return undef unless $ziptype == ZIP_GetNetInfo_Resp;
	my (%zoneinfo, $extra, $flags);
	($flags, @zoneinfo{'NetNum_start', 'NetNum_end', 'zonename', 'mcastaddr'},
			$extra) = unpack('xxCnnC/a*C/a*a*', $rbuf);
	if ($flags & ZIP_GNI_ZoneInvalid) {
		($zoneinfo{'default_zonename'}) = unpack('C/a*', $extra);
	}
	$zoneinfo{'ZoneInvalid'} = ($flags & ZIP_GNI_ZoneInvalid) ? 1 : 0;
	$zoneinfo{'UseBroadcast'} = ($flags & ZIP_GNI_UseBroadcast) ? 1 : 0;
	$zoneinfo{'OnlyOneZone'} = ($flags & ZIP_GNI_OnlyOneZone) ? 1 : 0;

	return { %zoneinfo };
}

1;
# vim: ts=4 ai
