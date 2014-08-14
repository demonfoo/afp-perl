# This UAM was added as of AFP 3.1.

package Net::AFP::UAMs::Reconnect;

use Net::AFP::Parsers;
use Net::AFP::TokenTypes;
use Digest::MD5 qw(md5);
use strict;
use warnings;

use Readonly;
Readonly my $UAMNAME => 'Recon1';

Readonly my $C2SIV => 'WOMDMOAB';
Readonly my $S2CIV => 'WOMDMOAB';

sub GetCred {
    my($session) = @_;

    my $ctx = $session->{'cryptctx'};
    unless (defined $ctx) {
        print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
        return undef;
    }

    my $stamp = time() - globalTimeOffset;
    my $ID = '';  # need to actually do something with this
    my $t1_k1 = $ctx->encrypt(pack('Na*', $stamp, $ID));
    my $resp = '';
    my $rc = $session->FPGetSessionToken($kRecon1Login, undef, $t1_k1, \$resp);
    if ($rc != $Net::AFP::Result::kFPNoErr) {
        print "Calling FPGetSessionToken failed\n";
        return undef;
    }

    my $token = $ctx->decrypt($resp);
    print "decrypted token data is: ", unpack('H*', $token), "\n";

    return 1;
}

sub RefreshCred {
    my($session) = @_;

    my $ctx = $session->{'cryptctx'};
    unless (defined $ctx) {
        print "No encryption context was stored; must use DHCAST128/DHX2 for Recon1!\n";
        return undef;
    }

    my $stamp = time() - globalTimeOffset;
    my $ID = '';  # need to actually do something with this
    $ctx->iv($C2SIV);
    my $t1_k1 = $ctx->encrypt(pack('Na*', $stamp, $ID));
    my $resp ;
    my $rc = $session->FPGetSessionToken($kRecon1RefreshToken, undef, $t1_k1, \$resp);
    if ($rc != $Net::AFP::Result::kFPNoErr) {
        print "Calling FPGetSessionToken failed\n";
        return undef;
    }
    #$ctx->iv($S2CIV);
    #my $plaintext = $ctx->decrypt($resp);
    #my($s, $m, $exp, $t3, $validator) = unpack('a[8]NNNa*', $plaintext);
    return($resp);
}

sub Reconnect {
    my($session, $AFPVersion, $username, $VolID, $Token) = @_;


}

die('Incomplete code, should not be used yet!');
1;
# vim: ts=4
