# This is Net::Atalk::ATP. It implements (mostly correctly) the ATP
# (AppleTalk Transaction Protocol) layer of the AppleTalk protocol
# family, which adds a transactional request/response layer over the
# DDP datagram protocol.
package Net::Atalk::ATP;

use strict;
use warnings;

# Disabling strict refs because for the installable transaction filters
# to work, I have to be able to have some way to deref the subroutines,
# and we can't pass SUB refs from thread to thread.
no strict qw(refs);

use IO::Socket::DDP;
use Net::Atalk;
use Time::HiRes qw(gettimeofday);
use IO::Poll qw(POLLIN);
use IO::Handle;
use threads;
use threads::shared;
use Thread::Semaphore;
use Exporter qw(import);

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

# symbols to export
our @EXPORT = qw(ATP_TREL_30SEC ATP_TREL_1MIN ATP_TREL_2MIN ATP_TREL_4MIN
		ATP_TREL_8MIN ATP_MAXLEN);

my $atp_header :shared;
$atp_header = 'CCCna[4]a*';
my @atp_header_fields :shared;
@atp_header_fields = ('ddp_type', 'ctl', 'bmp_seq', 'tid', 'userbytes',
		'payload');
my %xo_timeouts :shared;
%xo_timeouts = (
				 &ATP_TREL_30SEC	=> 30,
				 &ATP_TREL_1MIN		=> 60,
				 &ATP_TREL_2MIN		=> 120,
				 &ATP_TREL_4MIN		=> 240,
				 &ATP_TREL_8MIN		=> 480,
			   );


sub new { # {{{1
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
				 'RqCB_txq'		=> &share([]),
				 'RqCB_sem'		=> new Thread::Semaphore(0),
				 'RqFilters'	=> &share([]),
				 'RspCB_list'	=> &share({}),
			   );
	$$obj{'Shared'} = $shared;
	my $thread = threads->create(\&thread_core, $shared, %sockopts);
	$$obj{'Dispatcher'} = $thread;
	$$shared{'conn_sem'}->down();
	$$obj{'Conn'} = new IO::Handle;
	if ($$shared{'running'} == 1) {
		$$obj{'Conn'}->fdopen($$shared{'conn_fd'}, 'w');
	}
	$$shared{'conn_sem'}->up();

	return $obj;
} # }}}1

sub close { # {{{1
	my ($self) = @_;
	$$self{'Shared'}{'exit'} = 1;
	$$self{'Dispatcher'}->join();
} # }}}1

# This function is the body of the thread. Similar to DSI, this is a
# hybrid-dispatcher arrangement - responses are sent directly from the
# main thread, but messages coming from the peer are handled in the
# thread and processed and dispatched from there.
sub thread_core { # {{{1
	my ($shared, %sockopts) = @_;

	# Set up the datagram socket to the target host. There's no connection
	# status per-se, since DDP is datagram-oriented, not connection-oriented
	# like TCP is.
	my %connect_args = ( 'Proto'		=> 'ddp',
						 'Type'			=> SOCK_DGRAM,
						 %sockopts );
	my $conn = new IO::Socket::DDP(%connect_args);
	$$shared{'running'} = 1;

	$$shared{'conn_fd'} = fileno($conn);
	$$shared{'sockaddr'} = $conn->sockaddr();
	$$shared{'sockport'} = $conn->sockport();
	$$shared{'peeraddr'} = $conn->peeraddr();
	$$shared{'peerport'} = $conn->peerport();
	$$shared{'sockdomain'} = AF_APPLETALK;
	$$shared{'conn_sem'}->up();

	# Set up a poll object for checking out our socket. Also preallocate
	# several variables which will be used in the main loop.
	my $poll = new IO::Poll();
	$poll->mask($conn, POLLIN);
	my ($id, $TxCB, $sec, $usec, $delta, $from, $msg, %msgdata, $msgtype,
		$wants_sts, $is_eom, $seqno, $RqCB, $is_xo, $xo_tmout, $RspCB, $seq,
		$pktdata, $ctl_byte, $filter, $rv, $item, $stamp);

MAINLOOP:
	while ($$shared{'exit'} == 0) { # {{{2
		# Okay, now we need to check existing outbound transactions for
		# status, resends, cleanups, etc...
		($sec, $usec) = gettimeofday();
		foreach $id (keys %{$$shared{'TxCB_list'}}) { # {{{3
			$TxCB = $$shared{'TxCB_list'}{$id};
			$delta = ($sec - $$TxCB{'sec'}) +
					(($usec - $$TxCB{'usec'}) / 1000000);
			if ($delta >= $$TxCB{'tmout'}) {
				# We're past the indicated timeout duration for the
				# transaction, so now we have to decide its fate.
				if ($$TxCB{'ntries'} != 0) {
					# Packet data needs to be resent; sequence mask will
					# be updated in-place elsewhere, so just need to send
					# again, decrement the retry counter, and update
					# the start timer.

					# -1 is special, it means "just keep trying forever"
					if ($$TxCB{'ntries'} != -1) { $$TxCB{'ntries'}-- }

					$$shared{'conn_sem'}->down();
					send($conn, $$TxCB{'msg'}, 0, $$TxCB{'target'});
					@$TxCB{'sec', 'usec'} = ($sec, $usec); # close enough
					$$shared{'conn_sem'}->up();
				}
				else {
					# Okay, you've had enough go-arounds. Time to put
					# this dog down.
					${$$TxCB{'sflag'}} = 0;
					delete $$shared{'TxCB_list'}{$id};
					$$TxCB{'sem'}->up();
				}
			}
		} # }}}3

		# Check the XO transaction completion list as well.
		foreach $id (keys %{$$shared{'RspCB_list'}}) { # {{{3
			# If the transaction is past its keep-by, just delete it, nothing
			# more to be done on our end.
			$RspCB = $$shared{'RspCB_list'}{$id};
			$delta = ($sec - $$RspCB{'stamp'}[0]) +
					(($usec - $$RspCB{'stamp'}[1]) / 1000000);
			delete $$shared{'RspCB_list'}{$id} if $delta >= $$RspCB{'tmout'};
		} # }}}3

		# Check the socket for incoming packets.
		if ($poll->poll(0.5)) { # {{{3
			# We've got something. Read in a potential packet. We know it's
			# never going to be larger than DDP_MAXSZ.
			$$shared{'conn_sem'}->down();
			$from = recv($conn, $msg, DDP_MAXSZ, 0);
			$$shared{'conn_sem'}->up();
			next MAINLOOP unless defined $from;

			# Unpack the packet into its constituent fields, and quietly
			# move on if its DDP type field is wrong.
			@msgdata{@atp_header_fields} = unpack($atp_header, $msg);
			next MAINLOOP unless $msgdata{'ddp_type'} == DDPTYPE_ATP;

			# Let's see what kind of message we've been sent.
			$msgtype = $msgdata{'ctl'} & ATP_CTL_FNCODE;
			$id = $msgdata{'tid'};
			if ($msgtype == ATP_TReq) { # {{{4
				# Remote is asking to initiate a transaction with us.
				$is_xo = $msgdata{'ctl'} & ATP_CTL_XOBIT;
				$xo_tmout = $msgdata{'ctl'} & ATP_CTL_TREL_TMOUT;

				# Ignore a duplicate transaction request.
				next MAINLOOP if exists $$shared{'RqCB_list'}{$id};

				# If there's an XO completion handler in place, then resend
				# whatever packets the peer indicates it wants.
				if (exists $$shared{'RspCB_list'}{$id}) { # {{{5
					$RspCB = $$shared{'RspCB_list'}{$id};
					$RqCB = $$RspCB{'RqCB'};
					$pktdata = $$RspCB{'RespData'};

					for ($seq = 0; $seq < scalar(@$pktdata); $seq++) {
						# Check if the sequence mask bit corresponding to
						# the sequence number is set.
						next unless $$RqCB{'seq_bmp'} & (1 << $seq);

						$$shared{'conn_sem'}->down();
						send($conn, $$pktdata[$seq], 0, $$RqCB{'sockaddr'});
						$$shared{'conn_sem'}->up();
					}
					@{$$RspCB{'stamp'}} = gettimeofday();
					next MAINLOOP;
				} # }}}5
				$RqCB = &share({});
				# Set up the transaction request block.
				%$RqCB = (
						  'txid'		=> $id,
						  'is_xo'		=> $is_xo,
						  'xo_tmout_bits' => $xo_tmout,
						  'xo_tmout'	=> $xo_timeouts{$xo_tmout},
						  'seq_bmp'		=> $msgdata{'bmp_seq'},
						  'userbytes'	=> $msgdata{'userbytes'},
						  'payload'		=> $msgdata{'payload'},
						  'sockaddr'	=> $from,
						);

				# Try running the request block through any registered
				# transaction filter handlers before putting it on the
				# list for outside processing.
				foreach $filter (@{$$shared{'RqFilters'}}) { # {{{5
					$rv = &{$$filter[0]}(@$filter[1 .. $#$filter], $RqCB);
					# If the filter returned something other than undef,
					# it is (well, should be) an array ref containing
					# ATP user byte and payload blocks.
					if ($rv) { # {{{6
						$pktdata = &share([]);
						for ($seq = 0; $seq < scalar(@$rv); $seq++) {
							$item = $$rv[$seq];
							$ctl_byte = ATP_TResp;
							if ($$RqCB{'is_xo'}) {
								$ctl_byte |= ATP_CTL_XOBIT |
										$$RqCB{'xo_tmout_bits'};
							}
							# last packet in provided set, so tell the
							# requester that this is end of message...
							if ($seq == $#$rv) { $ctl_byte |= ATP_CTL_EOMBIT }
							$msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte,
									$seq, $id, @$item{'userbytes', 'payload'});
							$$pktdata[$seq] = $msg;

							next unless $$RqCB{'seq_bmp'} & (1 << $seq);

							# Okay, let's try registering the RspCB just
							# before the last packet posts to the server...
							if ($$RqCB{'is_xo'} && $seq == $#$rv) {
								$RspCB = &share({});
								$stamp = &share([]);
								@$stamp = gettimeofday();
								%$RspCB = (
									'RqCB'		=> $RqCB,
									'RespData'	=> $pktdata,
									'stamp'		=> $stamp,
									'tmout'		=> $$RqCB{'xo_tmout'},
								);
								$$shared{'RspCB_list'}{$id} = $RspCB;
							}

							$$shared{'conn_sem'}->down();
							send($conn, $msg, 0, $$RqCB{'sockaddr'});
							$$shared{'conn_sem'}->up();
						}
						next MAINLOOP;
					} # }}}6
				} # }}}5

				# FIXME: Perhaps the transaction queuing should be keyed on
				# a combination of the originator's address and port plus
				# the transaction ID? Seems like having just the txid could
				# end up causing conflicts...
				$$shared{'RqCB_list'}{$id} = $RqCB;
				push(@{$$shared{'RqCB_txq'}}, $RqCB);
				$$shared{'RqCB_sem'}->up();
			} # }}}4
			elsif ($msgtype == ATP_TResp) { # {{{4
				# Remote is responding to a transaction we initiated.

				# Ignore a transaction response to a transaction that we don't
				# know, either because we didn't initiate it, or because we
				# tried it enough times and gave up.
				next MAINLOOP unless exists $$shared{'TxCB_list'}{$id};

				# Get the transaction block, and grab a few bits of info
				# out of it to keep them at hand.
				$TxCB = $$shared{'TxCB_list'}{$id};
				$is_eom = $msgdata{'ctl'} & ATP_CTL_EOMBIT;
				$wants_sts = $msgdata{'ctl'} & ATP_CTL_STSBIT;
				$seqno = $msgdata{'bmp_seq'};

				# If the server says this packet is the end of the transaction
				# set, mask off any higher bits in the sequence bitmap.
				if ($is_eom) { $$TxCB{'seq_bmp'} &= 0xFF >> (7 - $seqno) }

				# If the sequence bit for this packet is already cleared,
				# just quietly move on.
				next MAINLOOP unless $$TxCB{'seq_bmp'} & (1 << $seqno);

				# Put data into the array of stored payloads.
				$$TxCB{'response'}[$seqno] = &share([]);
				@{$$TxCB{'response'}[$seqno]} = 
						@msgdata{'userbytes', 'payload'};
				# Clear the corresponding bit in the sequence bitmap.
				$$TxCB{'seq_bmp'} &= ~(1 << $seqno) & 0xFF;
				# Update packet data with new sequence bitmap.
				substr($$TxCB{'msg'}, 2, 1, pack('C', $$TxCB{'seq_bmp'}));

				# If the sequence bitmap is now 0, then we've received
				# all the data we're going to.
				unless ($$TxCB{'seq_bmp'}) { # {{{5
					${$$TxCB{'sflag'}} = 1;
					delete $$shared{'TxCB_list'}{$id};
					$$TxCB{'sem'}->up();

					# If it was an XO transaction, we should send a TRel here.
					if ($$TxCB{'is_xo'}) {
						$$TxCB{'ctl_byte'} &= ~ATP_CTL_FNCODE & 0xFF;
						$$TxCB{'ctl_byte'} |= ATP_TRel;
						substr($$TxCB{'msg'}, 1, 1,
								pack('C', $$TxCB{'ctl_byte'}));
						$$shared{'conn_sem'}->down();
						send($conn, $$TxCB{'msg'}, 0, $$TxCB{'target'});
						$$shared{'conn_sem'}->up();
					}
					next MAINLOOP;
				} # }}}5

				# If the server wants an STS, or the sequence number is
				# high enough that it's not going up further but there are
				# still packets we need, then resend the request packet.
				if ($wants_sts || ($$TxCB{'seq_bmp'} &&
						!($$TxCB{'seq_bmp'} >> $seqno))) {
					$$shared{'conn_sem'}->down();
					send($conn, $$TxCB{'msg'}, 0, $$TxCB{'target'});
					@$TxCB{'sec', 'usec'} = gettimeofday();
					$$shared{'conn_sem'}->up();
				}
			} # }}}4
			elsif ($msgtype == ATP_TRel) { # {{{4
				# Peer has sent us a transaction release message, so drop
				# the pending RspCB if one is present. I think we can
				# safely delete even if it's not there; saves us the time
				# of checking.
				delete $$shared{'RspCB_list'}{$id};
			} # }}}4
		} # }}}3
	} # }}}2
	# If we reach this point, we're exiting the thread. Notify any pending
	# waiting calls that they've failed before we go away.
	foreach $id (keys %{$$shared{'TxCB_list'}}) {
		$TxCB = $$shared{'TxCB_list'}{$id};
		${$$TxCB{'sflag'}} = 0;
		$$TxCB{'sem'}->up();
	}
	$$shared{'running'} = -1;
	undef $$shared{'conn_fd'};
	CORE::close($conn);
} # }}}1

sub SendTransaction { # {{{1
	my ($self, $is_xo, $target, $data, $user_bytes, $rlen, $rdata_r, $tmout,
			$ntries, $xo_tmout, $sflag_r) = @_;

	# Check a few parameters before we proceed.
	return if length($data) > ATP_MAXLEN;
	return if $rlen > 8;
	return if length($user_bytes) > 4;
	die('$rdata_r must be a scalar ref')
			unless ref($rdata_r) eq 'SCALAR' or ref($rdata_r) eq 'REF'
				or $rlen == 0;
	die('$sflag_r must be a scalar ref')
			unless ref($sflag_r) eq 'SCALAR' or ref($sflag_r) eq 'REF';

	# Set up the outgoing transaction request packet.
	my $ctl_byte = ATP_TReq;
	if ($is_xo) {
		$ctl_byte |= ATP_CTL_XOBIT | $xo_tmout;
	}
	my $seq_bmp = 0xFF >> (8 - $rlen);

	my $TxCB_queue = $$self{'Shared'}{'TxCB_list'};
	my $txid;
	# Okay, have to handle potential transaction ID collisions due to
	# wrapping...
	do {
		$txid = ++$$self{'Shared'}{'last_txid'} % (2 ** 16);
	} while (exists $$TxCB_queue{$txid});

	my $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq_bmp, $txid,
			$user_bytes, $data);

	# Don't register a transaction control block if the sender says the
	# response length is 0.
	return($txid, undef) if $rlen == 0;

	# Set up the transaction control block.
	my $TxCB = &share({});
	%$TxCB = (
				 'msg'		=> $msg,
				 'ntries'	=> $ntries == -1 ? $ntries : ($ntries - 1),
				 'response'	=> &share([]),
				 'ctl_byte'	=> $ctl_byte,
				 'seq_bmp'	=> $seq_bmp,
				 'is_xo'	=> $is_xo,
				 'tmout'	=> $tmout,
				 'sec'		=> undef,
				 'usec'		=> undef,
				 'sem'		=> new Thread::Semaphore(0),
				 'sflag'	=> &share($sflag_r),
				 'target'	=> $target,
			   );
	$$rdata_r = $$TxCB{'response'};

	# Indicate this as when the transaction has started (have to do this
	# before we queue the TxCB)...
	@$TxCB{'sec', 'usec'} = gettimeofday();

	# Register our transaction control block so the thread can see it,
	# since we have no idea how soon the response will come back from
	# who we're talking to.
	$$TxCB_queue{$txid} = $TxCB;

	# Send request packet.
	$$self{'Shared'}{'conn_sem'}->down();
	send($$self{'Conn'}, $msg, 0, $target);
	$$self{'Shared'}{'conn_sem'}->up();

	return($txid, $$TxCB{'sem'});
} # }}}1

sub GetTransaction { # {{{1
	my ($self, $do_block, $filter) = @_;

	# Get the ref for the queue of incoming transactions.
	my $RqCB_queue = $$self{'Shared'}{'RqCB_txq'};

	# Handle optionally blocking for a new transaction.
	if ($do_block) { $$self{'Shared'}{'RqCB_sem'}->down() }

	for (my $i = 0; $i < scalar(@$RqCB_queue); $i++) {
		# If no transaction filter was passed, or the transaction filter
		# returned true, grab the RqCB out of the queue, remove it from
		# the pending queue, and return it to the caller.
		if (!defined($filter) || &$filter($$RqCB_queue[$i])) {
			my $RqCB = $$RqCB_queue[$i];
			@$RqCB_queue = @$RqCB_queue[0 .. ($i - 1),
					($i + 1) .. $#$RqCB_queue];
			# If the caller asked to block to wait, restore the semaphore
			# count to where it should be.
			if ($do_block) {
				for (my $j = 0; $j < $i - 1; $j++) {
					$$self{'Shared'}{'RqCB_sem'}->up();
				}
			}
			return $RqCB;
		}
		# Down the sem again, so that if we're at the last, we'll block
		# until another is enqueued.
		if ($do_block) { $$self{'Shared'}{'RqCB_sem'}->down() }
	}
	# If we reach this point, the caller didn't ask to block *and* no
	# transactions matched (or none were in the waiting queue), so just
	# send back an undef.
	return undef;
} # }}}1

sub RespondTransaction { # {{{1
	my ($self, $txid, $resp_r) = @_;
	
	die('$resp_r must be an array') unless ref($resp_r) eq 'ARRAY';

	# If the transaction response is too big/small, just abort the whole
	# mess now.
	die('Ridiculous number of response packets supplied')
			if scalar(@$resp_r) > 8 or scalar(@$resp_r) < 1;

	# Abort if the transaction ID that the caller indicated is unknown to us.
	die() unless exists $$self{'Shared'}{'RqCB_list'}{$txid};
	my $RqCB = $$self{'Shared'}{'RqCB_list'}{$txid};

	my $pktdata = &share([]);

	for (my $seq = 0; $seq < scalar(@$resp_r); $seq++) {
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
		$$pktdata[$seq] = $msg;

		next unless $$RqCB{'seq_bmp'} & (1 << $seq);

		# Okay, let's try registering the RspCB just before the last packet
		# posts to the server...
		if ($$RqCB{'is_xo'} && $seq == $#$resp_r) {
			my $RspCB = &share({});
			my $stamp = &share([]);
			@$stamp = gettimeofday();
			%$RspCB = (
				'RqCB'		=> $RqCB,
				'RespData'	=> $pktdata,
				'stamp'		=> $stamp,
				'tmout'		=> $$RqCB{'xo_tmout'},
			);
			$$self{'Shared'}{'RspCB_list'}{$txid} = $RspCB;
		}

		$$self{'Shared'}{'conn_sem'}->down();
		send($$self{'Conn'}, $msg, 0, $$RqCB{'sockaddr'});
		$$self{'Shared'}{'conn_sem'}->up();
	}

	# Remove the transaction from the stored list.
	delete $$self{'Shared'}{'RqCB_list'}{$txid};
} # }}}1

# The idea here is to be able to pass a subroutine that looks at the
# transaction block and, if it's known, handle the transaction without
# passing it on to transaction queue at all.
sub AddTransactionFilter { # {{{1
	my ($self, $filter) = @_;

	push(@{$$self{'Shared'}{'RqFilters'}}, $filter);
} # }}}1

1;
# vim: ts=4 fdm=marker
