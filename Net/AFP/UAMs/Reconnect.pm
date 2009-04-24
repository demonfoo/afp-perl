
package Net::AFP::UAMs::Reconnect;

use Net::AFP::Parsers;
use Net::AFP::TokenTypes;
use strict;
use warnings;

use constant UAMNAME => 'Recon1';

sub GetCred {
	my($session) = @_;

	my $ctx = $session->{'cryptctx'};
	unless (defined $ctx) {
		print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
		return undef;
	}

	my $stamp = time() - $Net::AFP::Parsers::globalTimeOffset;
	my $t1_k1 = $ctx->encrypt(pack('N', $stamp));
	my $resp = '';
	my $ID = '';  # need to actually do something with this
	my $rc = $session->FPGetSessionToken(Net::AFP::TokenTypes::kRecon1Login,
			$t1_k1, $ID, \$resp);
	if ($rc != Net::AFP::Result::kFPNoErr) {
		print "Calling FPGetSessionToken failed\n";
		return undef;
	}

	my $token = $ctx->decrypt($resp);
	print "decrypted token data is: ", unpack('H*', $token), "\n";

	return 1;
}

sub RefreshCred {
	my($session) = @_;

}

sub Reconnect {
	my($session, $AFPVersion, $username, $VolID, $Token) = @_;


}

die('Incomplete code, should not be used yet!');
1;
# vim: ts=4
