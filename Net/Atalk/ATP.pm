package Net::Atalk::ATP;

use threads;
use threads::shared;
use Thread::Semaphore;
use strict;
use warnings;

# ATP message types.
use constant ATP_TReq			=> (0x1 << 6);	# Transaction request
use constant ATP_TResp			=> (0x2 << 6);	# Transaction response
use constant ATP_TRel			=> (0x3 << 6);	# Transaction release

# Fields of the control byte (first byte) in an ATP message.
use constant ATP_CTL_FNCODE		=> 0xC0;
use constant ATP_CTL_XOBIT		=> 0x20;
use constant ATP_CTL_EOMBIT		=> 0x10;
use constant ATP_CTL_STSBIT		=> 0x08;
use constant ATP_CTL_TREL_TMOUT	=> 0x07;

# TRel timeout periods for XO (exactly-once) transactions. Ignored by
# AppleTalk Phase1 implementations; I don't think this applies to anything
# except really, really old stuff.
use constant ATP_TREL_30SEC		=> 0x00;
use constant ATP_TREL_1MIN		=> 0x01;
use constant ATP_TREL_2MIN		=> 0x02;
use constant ATP_TREL_4MIN		=> 0x03;
use constant ATP_TREL_8MIN		=> 0x04;

# The maximum length of the ATP message body.
use constant ATP_MAXLEN			=> 578;

my $atp_header = 'CCnN';
my @atp_header_fields = ('ctl', 'bmp_seq', 'tid', 'msglen');

sub thread_proc {
	my ($shared, $host, $socket) = @_;

	my $conn;

	while ($$shared{'exit'} == 0) {
		if ($poll->poll(
}


