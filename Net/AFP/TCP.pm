# Implementation of a subclass that implements the necessary virtual methods
# for handling an AFP session over TCP protocol.
package Net::AFP::TCP;
use Net::DSI;
use Net::AFP;
use Net::AFP::Parsers;
use Net::AFP::Result;
use Exporter qw(import);
use strict;
use warnings;

=head1 NAME

Net::AFP::TCP - Perl module implementing AFP over TCP interface

=head1 DESCRIPTION

This package implements the necessary methods to interface to an
AFP over TCP server. It is a subclass of Net::AFP, which
implements the generic parts of the AFP protocol; this module adds
AFP over TCP specific code. See L<Net::AFP/AFP SERVER COMMANDS>
for a list of all the inherited methods which can be called against the
instantiated object.

=head1 METHODS

=over

=cut

our @ISA = qw(Net::AFP);
our @EXPORT = qw(kFPShortName kFPLongName kFPUTF8Name kFPSoftCreate
				 kFPHardCreate);

# Arguments:
#	$class: The class (Net::AFP::TCP) to create an instance of. This
#			must be invoked as 'new Net::AFP::TCP' or
#			'Net::AFP::TCP->new'.
#	$host: The IP address (a DNS name should work as well) of the AFP over
#		   TCP server we wish to connect to. (IPv6 addresses will work as
#		   well, if IO::Socket::INET6 is available.)
#	$port: The port to connect to. Should be 'undef' if the default port
#		   is to be used (default is 548).
=item new()

Create a new instance of a Net::AFP::TCP session. Should always
be called like:

Net::AFP::TCP->new(...);

or:

new Net::AFP::TCP (...);

DO NOT call:

Net::AFP::TCP::new(...);

This calling convention will not work.

=over

=item $host

IP address, or host name, of the target AFP server to initiate a connection
to. This argument is required.

=item $port

The TCP port number or system-defined service name representing the TCP
port to open the connection to. This argument is not required, and C<undef>
may be passed, or you may ignore it all together, if you wish to connect
to the standard TCP port for AFP over TCP services.

=back

Error replies (may not be comprehensive):

=over

=item kFPNoServer

Server was not connected.

=item kFPServerGoingDown

Server is shutting down.

=back

=cut
sub new { # {{{1
	my ($class, $host, $port) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $obj = {};
	bless $obj, $class;

	$$obj{'DSISession'} = new Net::DSI($host, $port);
	my $rc = $$obj{'DSISession'}->DSIOpenSession();
	return $rc unless $rc == kFPNoErr;
	return $obj;
} # }}}1

=item close()

Close an open connection to an AFP over TCP server. Any open files,
volumes and other handles should be closed out before this is called,
and FPLogout() should be called to close the session out.

=over

=item $self

An instance of Net::AFP::TCP which is to be shut down and
disbanded.

=back

Error replies:

None.

=cut

sub close { # {{{1
	my ($self) = @_;
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;

#	$$self{'DSISession'}->DSICloseSession();
	$$self{'DSISession'}->close();
} # }}}1

=item CheckAttnQueue()

=cut
sub CheckAttnQueue() {
	my ($self) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $attnq = $$self{'DSISession'}{'Shared'}{'attnq'};
	my $vol_update_checked;
	while (my $msg = shift(@$attnq)) {
		if ($msg & 0x8000) {	# server says it's shutting down
			print "CheckAttnQueue(): Received notification of server intent to shut down\n";
			print "Shutdown in ", ($msg & 0xFFF), " minutes\n";
			if ($msg & 0x2000) { # server also has a message for us
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					print "Shut down message: \"", $$MsgData{'ServerMessage'}, "\"\n";
				}
			}
		}
		elsif ($msg & 0x4000) { # server says it's crashing
			print "CheckAttnQueue(): Received notification server is crashing; should really attempt reconnection, I suppose...\n";
		}
		elsif ($msg & 0x2000) { # server message?
			if ($msg & 0x1001) { # server notification
				if ($msg & 0x1) {
					next if $vol_update_checked;
					print "CheckAttnQueue(): ModDate updated on an attached volume, should do FPGetVolParms() to recheck\n";
					$vol_update_checked = 1;
				}
			}
			else { # server message
				my $MsgData;
				$self->FPGetSrvrMsg(1, 3, \$MsgData);
				if ($$MsgData{'ServerMessage'} ne '') {
					print "Server message: \"", $$MsgData{'ServerMessage'}, "\"\n";
				}
			}
		}
	}
}

=item SendAFPMessage()

Private method, used internally by Net::AFP for dispatching
AFP requests. Do not use.

=cut
# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPMessage { # {{{1
	my($self, $payload, $resp_r) = @_;
	
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	$self->CheckAttnQueue();
	my $rc = $$self{'DSISession'}->DSICommand($payload, $resp_r);
	return $rc;
} # }}}1

=item SendAFPWrite()

Private method, used internally by Net::AFP for dispatching
AFP write requests. Do not use.

=cut
# This is a virtual method which is not for public consumption. Only
# Net::AFP methods should ever call this.
sub SendAFPWrite { # {{{1
	my($self, $payload, $data_r, $resp_r) = @_;
	
	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	$self->CheckAttnQueue();
	my $rc = $$self{'DSISession'}->DSIWrite($payload, $data_r, $resp_r);
	return $rc;
} # }}}1

=item GetStatus()

Requests information about an AFP over TCP server. Should not be called
against an open session; only call this method as follows:

Net::AFP::TCP->GetStatus(...);

Other calling conventions will not work correctly.

Note that this returns the same data structure that FPGetSrvrInfo() does, but
is intended for getting server information prior to setting up a full-on
session with the server.

=over

=item $host

The IP address, or host name, of the AFP over TCP server to connect to,
from which information is to be requested.

=item $port

The TCP port number or system-defined service name representing the TCP
port to open the connection to. This argument is not required, and C<undef>
may be passed if you wish to connect to the standard TCP port for AFP over
TCP services.

=item $resp_r

A scalar reference which will contain the parsed data structure from
the remote server upon success.

=back

=cut
sub GetStatus { # {{{1
	my ($class, $host, $port, $resp_r) = @_;
	if (ref($class)) {
		die('GetStatus() should NEVER be called against an active object');
		return -1;
	}

	print 'called ', (caller(0))[3], "\n" if defined $::__AFP_DEBUG;
	my $obj = new Net::DSI($host, $port);
	my $resp;
	my $rc = $obj->DSIGetStatus(\$resp);
	$obj->close();
	return $rc unless $rc == kFPNoErr;

	$$resp_r = Net::AFP::Parsers::_ParseSrvrInfo($resp);
	return $rc;
} # }}}1

=back

=cut
1;
# vim: ts=4 fdm=marker