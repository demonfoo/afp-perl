package Net::Atalk;

use Exporter;

use strict;
use warnings;

our @ISA = qw(Exporter);
our @EXPORT = qw(atalk_aton atalk_ntoa pack_sockaddr_at unpack_sockaddr_at
				 DDPTYPE_RTMPRD DDPTYPE_NBP DDPTYPE_ATP DDPTYPE_AEP
				 DDPTYPE_RTMPR DDPTYPE_ZIP DDPTYPE_ADSP );

=head1 NAME

Net::Atalk - Convenience functions for AppleTalk socket operations

=head1 SYNOPSIS

    use Net::Atalk;

=head1 DESCRIPTION

C<Net::Atalk> provides various common convenience functions for
operating on AppleTalk (DDP) sockets. Specifically, it contains
functions similar to the C<Socket> package for packing AppleTalk
host addresses, and packing addresses and ports into C<struct sockaddr_at>
structure format for AppleTalk socket operations.

=over

=item AF_APPLETALK

Symbolic representation for the AppleTalk address family identifier.

=cut
sub AF_APPLETALK { return 5; }
=item PF_APPLETALK

Symbolic representation for the AppleTalk protocol family identifier.

=cut
sub PF_APPLETALK { return AF_APPLETALK; }

use constant DDPTYPE_RTMPRD		=> 1;
use constant DDPTYPE_NBP		=> 2;
use constant DDPTYPE_ATP		=> 3;
use constant DDPTYPE_AEP		=> 4;
use constant DDPTYPE_RTMPR		=> 5;
use constant DDPTYPE_ZIP		=> 6;
use constant DDPTYPE_ADSP		=> 7;

use constant ATPORT_FIRST		=> 1;
use constant ATPORT_RESERVED	=> 128;
use constant ATPORT_LAST		=> 254; # only legal on localtalk
use constant ATADDR_ANYNET		=> 0;
use constant ATADDR_ANYNODE		=> 0;
use constant ATADDR_ANYPORT		=> 0;
use constant ATADDR_BCAST		=> 255;
use constant DDP_MAXSZ			=> 587;
use constant DDP_MAXHOPS		=> 15; # 4 bit hop counter

=item atalk_aton

Pack a string form AppleTalk host address.

=cut
sub atalk_aton {
	my($addr) = @_;

	my($net, $node) = $addr =~ /^(\d{1,5})\.(\d{1,3})$/;
	die() unless defined $net && defined $node;
	return pack('nC', $net, $node);
}

=item atalk_ntoa

Unpack a packed AppleTalk address back to string form.

=cut
sub atalk_ntoa {
	my($paddr) = @_;

	return sprintf('%d.%d', unpack('nC', $paddr));
}

=item sockaddr_at

If given a single argument, the argument is assumed to be a packed
C<struct sockaddr_at>, and is unpacked into the constituent port
number and packed AppleTalk host address.

If multiple arguments are given, the arguments are assumed to be a
port number and a packed AppleTalk host address, and a packed
C<struct sockaddr_at> is returned containing them.

=cut
sub sockaddr_at {
	if (scalar(@_) == 1) {
		return unpack_sockaddr_at(@_);
	} else {
		return pack_sockaddr_at(@_);
	}
}

=item pack_sockaddr_at

Accepts a DDP port number and a packed AppleTalk host address. Returns
a packed C<struct sockaddr_at> structure.

=cut
sub pack_sockaddr_at {
	my($port, $paddr) = @_;

	return pack('SCxa[3]x[9]', AF_APPLETALK, $port, $paddr);
}

=item unpack_sockaddr_at

Accepts a packed C<struct sockaddr_at>. Returns the DDP port number and
packed AppleTalk host address as an array.

=cut
sub unpack_sockaddr_at {
	my($psock) = @_;

	return unpack('x[2]Cxa[3]x[9]', $psock);
}
=back

=cut
1;
