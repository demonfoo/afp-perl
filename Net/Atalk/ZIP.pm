package Net::Atalk::ZIP;

use strict;
use warnings;
use diagnostics;

use IO::Socket::DDP;
use Net::Atalk;
use Net::Atalk::ATP;
use IO::Poll qw(POLLIN);
use POSIX qw(ETIMEDOUT);
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

	my $dest = pack_sockaddr_at($port, ATADDR_BCAST);
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
	my @data = unpack('xxC/(nC/a*)', $rbuf);
	my %namedata;
	while (scalar(@data)) {
		my $zonenum = shift(@data);
		my $zonename = shift(@data);
		unless (exists $namedata{$zonenum}) { $namedata{$zonenum} = [] }
		push(@{$namedata{$zonenum}}, $zonename);
	}

	return { %namedata };
}

=item ZIPGetZoneList (FROMADDR, STARTINDEX)

Get a list of known zones, starting at the given offset. Optionally specify
the local address to issue the queries from; C<undef> otherwise. Upon
success, returns an array reference containing the zone list.

=cut
sub ZIPGetZoneList {
	my ($FromAddr, $StartIndex) = @_;
	my %sockopts;
	if ($FromAddr) { $sockopts{'LocalAddr'} = $FromAddr }
	my $conn = new Net::Atalk::ATP(%sockopts);
	return undef unless defined $conn;

	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, ATADDR_ANY);

	my $user_bytes = pack('Cxn', ZIP_ATP_GetZoneList, $StartIndex);
	my $rdata;
	my $success;
	my $sem = $conn->SendTransaction(
		'UserBytes'			=> $user_bytes,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 5,
		'PeerAddr'			=> $dest,
	);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($LastFlag, $count) = unpack('Cxn', $$rdata[0][0]);
		my @zonenames = unpack('C/a*' x $count, $$rdata[0][1]);
		return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
	}
	$! = ETIMEDOUT;
	return undef;
}

=item ZIPGetLocalZones (FROMADDR, STARTINDEX)

Get a list of known zones for the local network segment, starting at
the given offset. Optionally specify the local address to issue the
queries from; C<undef> otherwise. Upon success, returns an array
reference containing the list of local zones.

=cut
sub ZIPGetLocalZones {
	my ($FromAddr, $StartIndex) = @_;
	my %sockopts;
	if ($FromAddr) { $sockopts{'LocalAddr'} = $FromAddr }
	my $conn = new Net::Atalk::ATP(%sockopts);
	return undef unless defined $conn;

	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, ATADDR_ANY);

	my $user_bytes = pack('Cxn', ZIP_ATP_GetLocalZones, $StartIndex);
	my $rdata;
	my $success;
	my $sem = $conn->SendTransaction(
		'UserBytes'			=> $user_bytes,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 5,
		'PeerAddr'			=> $dest,
	);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($LastFlag, $count) = unpack('Cxn', $$rdata[0][0]);
		my @zonenames = unpack('C/a*' x $count, $$rdata[0][1]);
		return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
	}
	$! = ETIMEDOUT;
	return undef;
}

=item ZIPGetMyZone (FROMADDR)

Get the zone the local machine is associated with. Optionally specify
the local address to issue the queries from; C<undef> otherwise. Upon
success, returns the name of the current host's assigned zone.

=cut
sub ZIPGetMyZone {
	my ($FromAddr) = @_;
	my %sockopts;
	if ($FromAddr) { $sockopts{'LocalAddr'} = $FromAddr }
	my $conn = new Net::Atalk::ATP(%sockopts);
	return undef unless defined $conn;

	my $port = getservbyname('zip', 'ddp') || 6;
	my $dest = pack_sockaddr_at($port, ATADDR_ANY);

	my $user_bytes = pack('Cxn', ZIP_ATP_GetMyZone, 0);
	my $rdata;
	my $success;
	my $sem = $conn->SendTransaction(
		'UserBytes'			=> $user_bytes,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 5,
		'PeerAddr'			=> $dest,
	);
	# block on the semaphore until the thread tells us we're done
	$sem->down();
	$conn->close();
	if ($success) {
		my ($count) = unpack('xxn', $$rdata[0][0]);
		die() if $count != 1;
		my ($zonename) = unpack('C/a*', $$rdata[0][1]);
		return $zonename;
	}
	$! = ETIMEDOUT;
	return undef;
}

=item ZIPGetNetInfo (ZONENAME) 

Inquire about network information for a specific AppleTalk zone. Returns a
hash ref, containing network number range and other information.

=cut
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

	my $dest = pack_sockaddr_at($port, ATADDR_BCAST);
	my $msg = pack('CCx[5]C/a*', DDPTYPE_ZIP, ZIP_GetNetInfo_Req, $zonename);
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
	$zoneinfo{'mcastaddr'} = join(':', unpack('H[2]' x 6, $zoneinfo{'mcastaddr'}));
	if ($flags & ZIP_GNI_ZoneInvalid) {
		($zoneinfo{'default_zonename'}) = unpack('C/a*', $extra);
	}
	$zoneinfo{'ZoneInvalid'} = ($flags & ZIP_GNI_ZoneInvalid) ? 1 : 0;
	$zoneinfo{'UseBroadcast'} = ($flags & ZIP_GNI_UseBroadcast) ? 1 : 0;
	$zoneinfo{'OnlyOneZone'} = ($flags & ZIP_GNI_OnlyOneZone) ? 1 : 0;

	return { %zoneinfo };
}

=back

=head1 REFERENCES

The Zone Information Protocol implementation contained herein is based
on the protocol description as provided by Apple, in the book "Inside
AppleTalk", chapter 8. "Inside AppleTalk" is available freely via the
Internet in PDF form, at:

L<http://developer.apple.com/MacOs/opentransport/docs/dev/Inside_AppleTalk.pdf>

Also, netatalk's libatalk and getzones tool were used as source references
for development (see L<http://netatalk.sourceforge.net/>).

=head1 SEE ALSO

L<Net::Atalk>, L<IO::Socket::DDP>

=cut
1;
# vim: ts=4 ai fdm=marker
