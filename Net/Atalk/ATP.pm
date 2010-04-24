package Net::Atalk::ATP;

use strict;
use warnings;

use IO::Socket::DDP;
use Net::Atalk;
use Time::HiRes qw(gettimeofday);
use IO::Poll qw(POLLIN);
use IO::Handle;
use threads;
use threads::shared;
use Thread::Semaphore;
use Data::Dumper;

# ATP message types.
use constant ATP_TReq			=> (0x1 << 6);	# Transaction request
use constant ATP_TResp			=> (0x2 << 6);	# Transaction response
use constant ATP_TRel			=> (0x3 << 6);	# Transaction release

# Fields of the control byte (first byte) in an ATP message.
use constant ATP_CTL_FNCODE		=> 0xC0;
use constant ATP_CTL_XOBIT		=> 0x20;	# transaction must happen
											# exactly once
use constant ATP_CTL_EOMBIT		=> 0x10;	# packet is end of message
use constant ATP_CTL_STSBIT		=> 0x08;	# send transaction status; upon
											# receipt by originator, resend
											# TReq packet
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

my $atp_header = 'CCCna[4]a*';
my @atp_header_fields = ('ddp_type', 'ctl', 'bmp_seq', 'tid', 'userbytes',
		'payload');

sub new {
	my ($class, %sockopts) = @_;

	my $obj = bless {}, $class;

	my $shared = &share({});
	%$shared = (
				 'running'		=> 0,
				 'exit'			=> 0,
				 'last_txid'	=> int(rand(2 ** 16)),
				 'conn_fd'		=> undef,
				 'conn_sem'		=> new Thread::Semaphore(0),
				 'TxCB_list'	=> &share({}),
				 'RqCB_list'	=> &share({}),
				 'RqCB_txidq'	=> &share([]),
				 'RspCB_list'	=> &share({}),
			   );
	$$obj{'Shared'} = $shared;
	my $thread = threads->create(\&thread_core, $shared, %sockopts);
	$$obj{'Dispatcher'} = $thread;
	print "new(): calling sem down op to wait for thread startup completion\n";
	$$shared{'conn_sem'}->down();
	print "new(): sem down completed\n";
	$$obj{'Conn'} = new IO::Handle;
	if ($$shared{'running'} == 1) {
		$$obj{'Conn'}->fdopen($$shared{'conn_fd'}, 'w');
	}
	$$shared{'conn_sem'}->up();

	return $obj;
}

sub close { # {{{1
	my ($self) = @_;
	$$self{'Shared'}{'exit'} = 1;
	$$self{'Dispatcher'}->join();
} # }}}1

# This function is the body of the thread. Similar to DSI, but I haven't
# yet decided between fully-dispatched and hybrid dispatched models;
# since the thread may have to resend the TReq packet an indeterminate
# number of times, it might be better to just hand it off to it in the
# first place. I'll see where things go.
sub thread_core {
	my ($shared, %sockopts) = @_;

	# Set up the datagram socket to the target host. There's no connection
	# status per-se, since DDP is datagram-oriented, not connection-oriented
	# like TCP is.
	my %connect_args = ( 'Proto'		=> 'ddp',
						 'Type'			=> SOCK_DGRAM,
						 %sockopts );
	my $conn = new IO::Socket::DDP(%connect_args);
	$$shared{'running'} = 1;

	# FIXME: any kind of session failure connection I can do from here?
	# thinking no, but we'll see.
	
	$$shared{'conn_fd'} = fileno($conn);
	$$shared{'running'} = 1;
	$$shared{'sockaddr'} = $conn->sockaddr();
	$$shared{'sockport'} = $conn->sockport();
	$$shared{'peeraddr'} = $conn->peeraddr();
	$$shared{'peerport'} = $conn->peerport();
	$$shared{'sockdomain'} = AF_APPLETALK;
	print "thread: calling sem up op to indicate completion\n";
	$$shared{'conn_sem'}->up();

	# Set up a poll object for checking out our socket. Also preallocate
	# several variables which will be used in the main loop.
	my $poll = new IO::Poll();
	$poll->mask($conn, POLLIN);
	my ($id, $TxCB, $sec, $usec, $delta, $from, $msg, %msgdata, $msgtype,
		$wants_sts, $is_eom, $seqno, $RqCB, $is_xo, $xo_tmout, $RspCB, $seq,
		$resp_r, $ctl_byte);

	my $atp_header = 'CCCna[4]a*';
	my @atp_header_fields = ('ddp_type', 'ctl', 'bmp_seq', 'tid', 'userbytes',
			'payload');

	my %xo_timeouts = (
						&ATP_TREL_30SEC	=> 30,
						&ATP_TREL_1MIN	=> 60,
						&ATP_TREL_2MIN	=> 120,
						&ATP_TREL_4MIN	=> 240,
						&ATP_TREL_8MIN	=> 480,
					  );

MAINLOOP:
	while ($$shared{'exit'} == 0) {
		# Okay, now we need to check existing outbound transactions for
		# status, resends, cleanups, etc...
		print "thread: scanning pending transaction list\n";
		($sec, $usec) = gettimeofday();
		foreach $id (keys %{$$shared{'TxCB_list'}}) {
			print "thread: txid ", $id, " pending\n";
			$TxCB = $$shared{'TxCB_list'}{$id};
			$delta = ($sec - $$TxCB{'sec'}) +
					(($usec - $$TxCB{'usec'}) / 1000000);
			if ($delta >= $$TxCB{'tmout'}) {
				print "thread: transaction is past expire\n";
				# okay, packet data needs to be resent; sequence mask
				# will be updated in-place elsewhere, so just need to
				# send again, decrement the retry counter, and update
				# the start timer.
				if ($$TxCB{'ntries'} > -1) {
					print "thread: transaction still has tries left, resending for another shot...\n";
					$$TxCB{'ntries'}--;
					$$shared{'conn_sem'}->down();
					send($conn, $$TxCB{'msg'}, 0);
					@$TxCB{'sec', 'usec'} = ($sec, $usec); # close enough
					$$shared{'conn_sem'}->up();
				}
				else {
					print "thread: okay, transaction has no more tries, closing it out\n";
					# Okay, you've had enough go-arounds. Time to put
					# this dog down.
					${$$TxCB{'sflag'}} = 0;
					delete $$shared{'TxCB_list'}{$id};
					$$TxCB{'sem'}->up();
				}
			}
		}

		print "thread: scanning exactly-once transaction list\n";
		foreach $id (keys %{$$shared{'RspCB_list'}}) {
			print "thread: txid ", $id, " XO response block pending\n";
			$RspCB = $$shared{'RspCB_list'}{$id};
			$delta = ($sec - $$RspCB{'stamp'}[0]) +
					(($usec - $$RspCB{'stamp'}[1]) / 1000000);
			if ($delta >= $$RspCB{'tmout'}) {
				print "thread: XO response block for txid $id too old, pruning\n";
				delete $$shared{'RspCB_list'}{$id};
			}
		}
		if ($poll->poll(1)) {
			$$shared{'conn_sem'}->down();
			$from = recv($conn, $msg, DDP_MAXSZ, 0);
			$$shared{'conn_sem'}->up();
			next MAINLOOP unless defined $from;

			@msgdata{@atp_header_fields} = unpack($atp_header, $msg);
			unless ($msgdata{'ddp_type'} == DDPTYPE_ATP) {
				print "thread: packet received, but type was not DDPTYPE_ATP, ignoring\n";
				next MAINLOOP;
			}
			$msgtype = $msgdata{'ctl'} & ATP_CTL_FNCODE;
			$id = $msgdata{'tid'};
			if ($msgtype == ATP_TReq) {
				print "thread: received a transaction request\n";
				$is_xo = $msgdata{'ctl'} & ATP_CTL_XOBIT;
				$xo_tmout = $msgdata{'ctl'} & ATP_CTL_TREL_TMOUT;

				if (exists $$shared{'RqCB_list'}{$id}) {
					print "thread: transaction request already exists for txid ", $id, ", ignoring\n";
					next MAINLOOP;
				}
				if (exists $$shared{'RspCB_list'}{$id}) {
					$RspCB = $$shared{'RspCB_list'}{$id};
					$RqCB = $$RspCB{'RqCB'};
					$resp_r = $$RspCB{'RespData'};
					print "thread: txid $id has a response callback block associated, will attempt resend of indicated packets\n";

					# FIXME: Could probably save the precooked packets instead
					# of generating them here again...
					for (my $seq = 0; $seq < scalar(@$resp_r); $seq++) {
						next unless $$RqCB{'seq_bmp'} & (1 << $seq);
						print "thread: Resending packet $seq to requester\n";

						$ctl_byte = ATP_TResp | ATP_CTL_XOBIT |
								$$RqCB{'xo_tmout_bits'};
						if ($seq == $#$resp_r) { $ctl_byte |= ATP_CTL_EOMBIT }
						$msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq,
								$id, @{$$resp_r[$seq]}{'userbytes', 'payload'});
						$$shared{'conn_sem'}->down();
						send($conn, $msg, 0, $$RqCB{'sockaddr'});
						$$shared{'conn_sem'}->up();
						print "thread: Response packet $seq resent\n";
					}
					@{$$RspCB{'stamp'}} = gettimeofday();
					next MAINLOOP;
				}
				$RqCB = {
						  'txid'		=> $id,
						  'is_xo'		=> $is_xo,
						  'xo_tmout_bits' => $xo_tmout,
						  'xo_tmout'	=> $xo_timeouts{$xo_tmout},
						  'seq_bmp'		=> $msgdata{'bmp_seq'},
						  'userbytes'	=> $msgdata{'userbytes'},
						  'payload'		=> $msgdata{'payload'},
						  'sockaddr'	=> $from,
						};
				$$shared{'RqCB_list'}{$id} = $RqCB;
				push(@{$$shared{'RqCB_txidq'}}, $id);
				print "thread: set up request callback for transaction request with txid ", $id, "\n";
			}
			elsif ($msgtype == ATP_TResp) {
				print "thread: received a transaction response packet for txid ", $id, ", let's see who it belongs to\n";
				unless (exists $$shared{'TxCB_list'}{$id}) {
					print "thread: txid is ", $id, " but no corresponding TxCB was found, moving on\n";
					next MAINLOOP;
				}

				$TxCB = $$shared{'TxCB_list'}{$id};
				$is_eom = $msgdata{'ctl'} & ATP_CTL_EOMBIT;
				$wants_sts = $msgdata{'ctl'} & ATP_CTL_STSBIT;
				$seqno = $msgdata{'bmp_seq'};

				if ($is_eom) {
					print "thread: server says this packet is last in sequence, fixing up seq bitmap\n";
					printf("thread: seq bmp was 0x\%02x for txid %u\n", $$TxCB{'seq_bmp'}, $id);
					$$TxCB{'seq_bmp'} &= 0xFF >> (7 - $seqno);
					printf("thread: seq bmp is now 0x\%02x for txid %u\n", $$TxCB{'seq_bmp'}, $id);
				}
				if ($wants_sts) {
					print "thread: server wants us to send back transaction status\n";
				}
				if ($$TxCB{'seq_bmp'} & (1 << $seqno)) {
					print "thread: received packet with seq no ", $seqno, ", appears not to be a dup\n";
					# put data into the array of stored payloads
					$$TxCB{'response'}[$seqno] = &share([]);
					@{$$TxCB{'response'}[$seqno]} = 
							@msgdata{'userbytes', 'payload'};
					# clear the bit in the sequence bitmap
					$$TxCB{'seq_bmp'} &= ~(1 << $seqno) & 0xFF;
					# update packet data with new sequence bitmap
					substr($$TxCB{'msg'}, 2, 1, pack('C', $$TxCB{'seq_bmp'}));
				}
				else {
					print "thread: received packet with seq no ", $seqno, ", already received, ignoring\n";
				}

				unless ($$TxCB{'seq_bmp'}) {
					print "thread: okay, appears transaction is complete, indicating success and notifying caller\n";
					# if this is the case, we've received everything we're
					# expecting from the server side, so we've succeeded...
					${$$TxCB{'sflag'}} = 1;
					delete $$shared{'TxCB_list'}{$id};
					$$TxCB{'sem'}->up();
					# if it was an XO transaction, we should send a TRel here
					if ($$TxCB{'is_xo'}) {
						print "thread: transaction is XO, so will send TRel to server\n";
						$$TxCB{'ctl_byte'} &= ~ATP_CTL_FNCODE & 0xFF;
						$$TxCB{'ctl_byte'} |= ATP_TRel;
						substr($$TxCB{'msg'}, 1, 1,
								pack('C', $$TxCB{'ctl_byte'}));
						$$shared{'conn_sem'}->down();
						send($conn, $$TxCB{'msg'}, 0);
						$$shared{'conn_sem'}->up();
					}
					next MAINLOOP;
				}

				# if the server wants an STS, or the sequence number is
				# high enough that it's not going up further but there are
				# still packets we need, then resend the request packet.
				if ($wants_sts || ($$TxCB{'seq_bmp'} &&
						($$TxCB{'seq_bmp'} >> $seqno))) {
					print "thread: resending request packet for STS or to satisfy missing chunks\n";
					$$shared{'conn_sem'}->down();
					send($conn, $$TxCB{'msg'}, 0);
					@$TxCB{'sec', 'usec'} = gettimeofday();
					$$shared{'conn_sem'}->up();
				}
			}
			elsif ($msgtype == ATP_TRel) {
				print "thread: received a transaction release\n";
				if (exists $$shared{'RqCB_list'}{$id}) {
					print "thread: RspCB for txid $id found, removing\n";
					delete $$shared{'RqCB_list'}{$id};
				}
			}
		}
	}
	$$shared{'running'} = -1;
	undef $$shared{'conn_fd'};
	CORE::close($conn);
}

# FIXME: Think I need to handle a situation where a transaction is
# dispatched but no response is expected...
# FIXME: Also need to handle infinite tries, currently don't think it'd
# work right/at all.
sub SendTransaction {
	my ($self, $is_xo, $target, $data, $user_bytes, $rlen, $rdata_r, $tmout,
			$ntries, $xo_tmout, $sflag_r) = @_;

	# Check a few parameters before we proceed.
	return if length($data) > ATP_MAXLEN;
	return if $rlen > 8;
	return if length($user_bytes) > 4;
	die('$rdata_r must be a scalar ref')
			unless ref($rdata_r) eq 'SCALAR' or ref($rdata_r) eq 'REF';
	die('$sflag_r must be a scalar ref')
			unless ref($sflag_r) eq 'SCALAR' or ref($sflag_r) eq 'REF';

	# Set up the outgoing transaction request packet.
	my $ctl_byte = ATP_TReq;
	if ($is_xo) {
		$ctl_byte |= ATP_CTL_XOBIT | $xo_tmout;
	}
	my $seq_bmp = 0xFF >> (8 - $rlen);
	my $txid = ++$$self{'Shared'}{'last_txid'} % (2 ** 16);
	my $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq_bmp, $txid,
			$user_bytes, $data);

	# Set up the transaction control block.
	my $TxCB = &share({});
	%$TxCB = (
				 'msg'		=> $msg,
				 'ntries'	=> $ntries - 1, # one less, since this is
											# already try number one...
				 'response'	=> &share([]),
				 'ctl_byte'	=> $ctl_byte,
				 'seq_bmp'	=> $seq_bmp,
				 'is_xo'	=> $is_xo,
				 'tmout'	=> $tmout,
				 'sec'		=> undef,
				 'usec'		=> undef,
				 'sem'		=> new Thread::Semaphore(0),
				 'sflag'	=> &share($sflag_r),
			   );
	$$rdata_r = $$TxCB{'response'};
	# Register our transaction control block so the thread can see it,
	# since we have no idea how soon the response will come back from
	# who we're talking to.
	$$self{'Shared'}{'TxCB_list'}{$txid} = $TxCB;
	print "SendTransaction(): Queued transaction block as txid ", $txid, "\n";

	# indicate this as when the transaction has started
	@$TxCB{'start_sec', 'start_usec'} = gettimeofday();

	$$self{'Shared'}{'conn_sem'}->down();
	send($$self{'Conn'}, $msg, 0, $target);
	$$self{'Shared'}{'conn_sem'}->up();
	print "SendTransaction(): Sent request packet to server\n";

	return($txid, $$TxCB{'sem'});
}

sub GetTransaction {
	my ($self) = @_;

	unless (scalar(@{$$self{'Shared'}{'RqCB_txidq'}})) {
		print "GetTransaction(): No unchecked incoming transactions to return, returning undef\n";
		return undef;
	}
	my $txid = shift(@{$$self{'Shared'}{'RqCB_txidq'}});
	print "GetTransaction(): Returning transaction request block for txid ", $txid, "\n";
	return $$self{'Shared'}{'RqCB_list'}{$txid};
}

sub RespondTransaction {
	my ($self, $txid, $resp_r) = @_;
	
	die('$resp_r must be an array') unless ref($resp_r) eq 'ARRAY';

	die('Ridiculous number of response packets supplied')
			if scalar(@$resp_r) > 8 or scalar(@$resp_r) < 1;

	die() unless exists $$self{'Shared'}{'RqCB_list'}{$txid};
	my $RqCB = $$self{'Shared'}{'RqCB_list'}{$txid};
	print "RespondTransaction(): Found transaction block for txid $txid\n";

	for (my $seq = 0; $seq < scalar(@$resp_r); $seq++) {
		next unless $$RqCB{'seq_bmp'} & (1 << $seq);
		print "RespondTransaction(): Sending packet $seq to requester\n";
		
		die('$resp_r element ' . $seq . ' was not a hash ref')
				unless ref($$resp_r[$seq]) eq 'HASH';
		my $ctl_byte = ATP_TResp;
		if ($$RqCB{'is_xo'}) {
			$ctl_byte |= ATP_CTL_XOBIT | $$RqCB{'xo_tmout_bits'};
		}
		# last packet in provided set, so tell the requester that this is
		# end of message...
		if ($seq == $#$resp_r) { $ctl_byte |= ATP_CTL_EOMBIT }
		my $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq, $txid,
				@{$$resp_r[$seq]}{'userbytes', 'payload'});
		$$self{'Shared'}{'conn_sem'}->down();
		send($$self{'Conn'}, $msg, 0, $$RqCB{'sockaddr'});
		$$self{'Shared'}{'conn_sem'}->up();
		print "RespondTransaction(): Response packet $seq sent\n";
	}
	# Now must hand off to XO protection layer if 'is_xo' is true...
	if ($$RqCB{'is_xo'}) {
		&share($resp_r);
		foreach (@$resp_r) { &share($_) }
		$$self{'Shared'}{'RspCB_list'}{$txid} = {
			'RqCB'		=> $RqCB,
			'RespData'	=> $resp_r,
			'stamp'		=> [ gettimeofday() ],
			'tmout'		=> $$RqCB{'xo_tmout'},
		};
	}

	# Remove the transaction from the stored list.
	delete $$self{'Shared'}{'RqCB_list'}{$txid};
}

1;
