package Net::Atalk::DDP;

use IO::Socket;

use strict;
use warnings;

use constant AF_APPLETALK => 5;
use constant PF_APPLETALK => AF_APPLETALK;

sub atalk_aton {
	my($addr) = @_;

	my($net, $node) = $addr =~ /^(\d{1,5})\.(\d{1,3})$/
	die() unless defined $net && defined $node;
	return pack('nC', $net, $node);
}

sub atalk_ntoa {
	my($paddr) = @_;

	return sprintf('%d.%d', unpack('nC', $paddr));
}

sub sockaddr_at {
	my($port, $paddr) = @_

	return pack('nCa[3]x[8]', AF_APPLETALK, $port, $paddr);
}

sub new {
	my($class, $addr, $port) = @_;
	my $sockaddr = sockaddr_at($port, atalk_aton($addr));

	my $sock = new IO::Socket('Domain' => AF_APPLETALK);
	return
}

1;
