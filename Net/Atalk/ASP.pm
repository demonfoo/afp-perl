# This is Net::Atalk::ASP. It will eventually implement the ASP (AppleTalk
# Session Protocol) layer of the AppleTalk protocol family. It should have
# a programming interface similar to Net::DSI; DSI was designed to layer
# over TCP/IP in a similar request/response fashion to ASP.
package Net::Atalk::ASP;

use Net::Atalk::ATP;
use IO::Poll qw(POLLRDNORM POLLWRNORM POLLIN POLLHUP);
use IO::Handle;
use Net::AFP::Result;
use threads;
use threads::shared;
use Thread::Semaphore;
use strict;
use warnings;

our $::__ASP_DEBUG = 1;

use constant SP_VERSION				=> 0x0100;

use constant OP_SP_CLOSESESS		=> 1;
use constant OP_SP_COMMAND			=> 2;
use constant OP_SP_GETSTATUS		=> 3;
use constant OP_SP_OPENSESS			=> 4;
use constant OP_SP_TICKLE			=> 5;
use constant OP_SP_WRITE			=> 6;
use constant OP_SP_WRITECONTINUE	=> 7;
use constant OP_SP_ATTENTION		=> 8;

sub SPGetParms {
	my ($self, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
}

sub SPGetStatus {
	my ($self, $SLSEntityIdentifier, $StatusBuffer, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	my $msg = pack('CCn', OP_SP_GETSTATUS, 0, 0);
}

sub SPOpenSession {
	my ($self, $SLSEntityIdentifier, $AttnRoutine, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	my $wss = 0;	# FIXME: Needs to get local socket number
	my $msg = pack('CCn', OP_SP_OPENSESS, $wss, SP_VERSION);
}

sub SPCloseSession {
	my ($self, $SessRefNum) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
	my $msg = pack('CCn', OP_SP_CLOSESESS, $SessRefNum, 0);
}

sub SPCommand {
	my ($self, $SessRefNum, $CmdBlock, $ReplyBuffer, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
}

sub SPWrite {
	my ($self, $SessRefNum, $CmdBlock, $WriteData, $ReplyBuffer, $resp_r) = @_;

	print 'called ', (caller(0))[3], "\n" if defined $::__ASP_DEBUG;
}





1;
# vim: ts=4 fdm=marker
