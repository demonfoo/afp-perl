# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over TCP protocol.
package Net::AFP::Connection::TCP;
use Net::DSI::Session;
use Net::AFP::Connection;
use Net::AFP::Parsers;
use Net::AFP::Result;
use strict;
use warnings;

our @ISA = qw(Net::AFP::Connection);

# Arguments:
#	$class: The class (Net::AFP::Connection::TCP) to create an instance of. This
#			must be invoked as 'new Net::AFP::Connection::TCP' or
#			'Net::AFP::Connection::TCP->new'.
#	$host: The IP address (a DNS name should work as well) of the AFP over
#		   TCP server we wish to connect to. (IPv6 addresses will work as
#		   well, if IO::Socket::INET6 is available.)
#	$port: The port to connect to. Should be 'undef' if the default port
#		   is to be used (default is 548).
sub new { # {{{1
	my ($class, $host, $port) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $obj = {};
	bless $obj, $class;

	$obj->{'DSISession'} = new Net::DSI::Session($host, $port);
	my $rc = $obj->{'DSISession'}->DSIOpenSession();
	return $rc unless $rc == Net::AFP::Result::kFPNoErr;
	return $obj;
} # }}}1

sub close { # {{{1
	my ($self) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

#	$self->{'DSISession'}->DSICloseSession();
	$self->{'DSISession'}->close();
} # }}}1

sub SendAFPMessage { # {{{1
	my($self, $payload, $resp_r) = @_;
	
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $rc = $self->{'DSISession'}->DSICommand($payload, $resp_r);
	return $rc;
} # }}}1

sub SendAFPWrite { # {{{1
	my($self, $payload, $data, $resp_r) = @_;
	
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $rc = $self->{'DSISession'}->DSIWrite($payload, $data, $resp_r);
	return $rc;
} # }}}1

sub FPGetSrvrInfo { # {{{1
	my ($class, $host, $port, $resp_r) = @_;
	if (ref($class) ne '') {
		die('FPGetSrvrInfo() should NEVER be called against an active object');
		return -1;
	}

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $resp = '';
	my $rc = Net::DSI::Session->DSIGetStatus($host, $port, \$resp);
	return $rc unless $rc == Net::AFP::Result::kFPNoErr;

	$$resp_r = Net::AFP::Parsers::_ParseSrvrInfo($resp);
	return $rc;
} # }}}1

1;
# vim: ts=4 fdm=marker
