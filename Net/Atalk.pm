package Net::Atalk;

use Exporter;

use strict;
use warnings;

our @ISA = qw(Exporter);
our @EXPORT = qw(atalk_aton atalk_ntoa pack_sockaddr_at unpack_sockaddr_at
				 DDPTYPE_RTMPRD DDPTYPE_NBP DDPTYPE_ATP DDPTYPE_AEP
				 DDPTYPE_RTMPR DDPTYPE_ZIP DDPTYPE_ADSP );

sub AF_APPLETALK { return 5; }
sub PF_APPLETALK { return AF_APPLETALK; }

use constant DDPTYPE_RTMPRD	=> 1;
use constant DDPTYPE_NBP	=> 2;
use constant DDPTYPE_ATP	=> 3;
use constant DDPTYPE_AEP	=> 4;
use constant DDPTYPE_RTMPR	=> 5;
use constant DDPTYPE_ZIP	=> 6;
use constant DDPTYPE_ADSP	=> 7;

sub atalk_aton {
	my($addr) = @_;

	my($net, $node) = $addr =~ /^(\d{1,5})\.(\d{1,3})$/;
	die() unless defined $net && defined $node;
	return pack('nC', $net, $node);
}

sub atalk_ntoa {
	my($paddr) = @_;

	return sprintf('%d.%d', unpack('nC', $paddr));
}

sub sockaddr_at {
	if (scalar(@_) == 1) {
		return unpack_sockaddr_at(@_);
	} else {
		return pack_sockaddr_at(@_);
	}
}

sub pack_sockaddr_at {
	my($port, $paddr) = @_;

	return pack('SCxa[3]x[9]', AF_APPLETALK, $port, $paddr);
}

sub unpack_sockaddr_at {
	my($psock) = @_;

	return unpack('nxa[3]x[8]', $psock);
}

1;
