# This package fairly correctly implements the DHX (aka DHCAST128) User
# Authentication Method for AFP sessions. It uses a Diffie-Hellman key
# exchange to establish a keyset that can be used for (reasonably) secure
# password-based authentication without the need for prehashed passwords.
# It requires the Crypt::CBC module to provide a cipher-block-chaining
# layer, and Crypt::CAST5 to provide the CAST5 (aka CAST128) encryption
# method used to secure the data over the wire. Math::BigInt::GMP is
# recommended for fast large-integer operations, as Math::BigInt::Calc
# works but is quite slow.

# This UAM was added as of AFP 3.0. (Later backported to Classic - AFP 2.3?)

package Net::AFP::UAMs::DHX;
use strict;
use warnings;

use constant UAMNAME => 'DHCAST128';

use constant C2SIV => 'LWallace';
use constant S2CIV => 'CJalbert';

# Provides the encryption algorithm.
my $has_Crypt__CAST5_PP = 0;
eval {
    require Crypt::CAST5_PP;
    1;
} and do {
    $has_Crypt__CAST5_PP = 1;
    Crypt::CAST5_PP->import;
};

my $has_Crypt__CAST5 = 0;
eval {
    require Crypt::CAST5;
    1;
} and do {
    $has_Crypt__CAST5 = 1;
    Crypt::CAST5->import;
};
die("No CAST5 implementation was available?")
        unless $has_Crypt__CAST5 || $has_Crypt__CAST5_PP;
# Provides the cipher-block chaining layer over the encryption algorithm.
use Crypt::CBC;
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
# Provides large-integer mathematics features, necessary for the
# cryptographic exchanges and derivation of the key. Fast, but the
# non-threaded to threaded changeover hoses it, so don't create Math::BigInt
# objects until after threads are started.
use Math::BigInt lib => 'GMP';
use Net::AFP::Versions;
use Log::Log4perl qw(:easy);

Net::AFP::UAMs::RegisterUAM(UAMNAME, __PACKAGE__, 150);

# These are universal. This particular UAM ALWAYS uses these values - $g
# as the base for an exponentiation, and $p as a modulus.
my @p_bytes = (0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57, 0xd4, 0x3f, 0x20,
			   0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b);
my @g_bytes = (0x07);

sub zeropad { return('0' x ($_[1] - length($_[0])) . $_[0]); }

sub Authenticate {
	my($session, $AFPVersion, $username, $pw_cb) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP!')
			unless ref($session) and $session->isa('Net::AFP');

	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	# Moving these into the functions, to make Math::BigInt::GMP happy.
	my $p = new Math::BigInt('0x' . unpack('H*', pack('C*', @p_bytes)));
	my $g = new Math::BigInt('0x' . unpack('H*', pack('C*', @g_bytes)));

	my $nonce_limit = new Math::BigInt(1);
	$nonce_limit->blsft(128);

	# Get random bytes that constitute a large exponent for the random number
	# exchange we do.
	my $Ra_binary = Crypt::CBC->_get_random_bytes(32);
	my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
	undef $Ra_binary;
	DEBUG('$Ra is ', $Ra->as_hex());

	# Ma = g^Ra mod p <- This gives us the "random number" that we hand to
	# the server.
	my $Ma = $g->bmodpow($Ra, $p);
	my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), 32));
	DEBUG('$Ma is ', $Ma->as_hex());
	undef $Ma;
	
	# Send the "random number" to the server as the first stage of the
	# authentication process, along with the username.
	my $authinfo = pack('C/a*x![s]a*', $username, $Ma_binary);
	DEBUG('$authinfo is 0x', unpack('H*', $authinfo));
	my %resp;
	my $rc;
	
	if (Net::AFP::Versions::CompareByVersionNum($AFPVersion, 3, 1,
			kFPVerAtLeast)) {
		($rc, %resp) = $session->FPLoginExt(
                'AFPVersion'    => $AFPVersion,
                'UAM'           => UAMNAME,
                'UserName'      => $username,
                'UserAuthInfo'  => $Ma_binary);
		DEBUG('FPLoginExt() completed with result code ', $rc);
	}
	else {
		my $authinfo = pack('C/a*x![s]a*', $username, $Ma_binary);
		($rc, %resp) = $session->FPLogin($AFPVersion, UAMNAME, $authinfo);
		DEBUG('FPLogin() completed with result code ', $rc);
	}
	undef $Ma_binary;
	undef $authinfo;
	return $rc unless $rc == kFPAuthContinue;
	my ($Mb_binary, $message) = unpack('a16a*', $resp{'UserAuthInfo'});
	my $Mb = new Math::BigInt('0x' . unpack('H*', $Mb_binary));
	undef $Mb_binary;
	DEBUG('$Mb is ', $Mb->as_hex());
	DEBUG('$message is 0x', unpack('H*', $message));

	# K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
	# and decrypt ciphertext for communicating with the server.
	my $K = $Mb->bmodpow($Ra, $p);
	undef $Ra;
	undef $Mb;
	my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), 32));
	DEBUG('$K is ', $K->as_hex());
	undef $K;

	# Set up an encryption context with the key we derived, and decrypt the
	# ciphertext that the server sent back to us.

	# NOTE NOTE NOTE: If this UAM breaks, see the docs for Crypt::CBC.
	# Its developer thinks it's a great idea to keep adding parameters
	# which then break expected behavior for those coding against it.
	# This code is PERFECT. It is 100% in line with Apple's docs.
	my $ctx = new Crypt::CBC( {	'key'				=> $K_binary,
								'cipher'			=> $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
								'padding'			=> 'null',
								'regenerate_key'	=> 0,
								'prepend_iv'		=> 0,
								'iv'				=> S2CIV } );
	undef $K_binary;
	$$session{'cryptctx'} = $ctx;
	# Set the "magic" IV that allows us to properly decrypt what the server
	# sends to us.
	#$ctx->set_initialization_vector(S2CIV);
	my $decrypted = $ctx->decrypt($message);
	# HACK ALERT: seems decrypt() likes to drop the trailing null on me :|
	# this line should pad out to the appropriate length, which should
	# avoid this problem...
	$decrypted .= "\0" x (32 - length($decrypted));
	DEBUG('$decrypted is 0x', unpack('H*', $decrypted));
	my ($nonce_binary, $serverSig) = unpack('a16a*', $decrypted);
	undef $decrypted;
	DEBUG('$serverSig is 0x', unpack('H*', $serverSig));
	undef $serverSig;

	# The nonce is a random value that the server sends as a check; we add
	# one to it, and send it back to the server to prove we understand what
	# it's saying.
	my $nonce = new Math::BigInt('0x' . unpack('H*', $nonce_binary));
	undef $nonce_binary;
	DEBUG('$nonce is ', $nonce->as_hex());
	$nonce->badd(1);
	$nonce = $nonce->bmod($nonce_limit);
	DEBUG('$nonce is ', $nonce->as_hex(), " after increment");
	my $newnonce_text = substr($nonce->as_hex(), 2);
	undef $nonce;
	my $authdata = pack('H*a64', zeropad($newnonce_text, 32), &$pw_cb());
	undef $newnonce_text;
	$ctx->set_initialization_vector(C2SIV);
	my $ciphertext = $ctx->encrypt($authdata);
	undef $authdata;
	DEBUG('$ciphertext is 0x', unpack('H*', $ciphertext));

	# Send the response back to the server, and hope we did this right.
	$rc = $session->FPLoginCont($resp{'ID'}, $ciphertext);
	undef $ciphertext;
	DEBUG('FPLoginCont() completed with result code ', $rc);
	return $rc;
}

sub ChangePassword {
	my($session, $username, $oldPassword, $newPassword) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP!')
			unless ref($session) and $session->isa('Net::AFP');

	# Moving these into the functions, to make Math::BigInt::GMP happy.
	my $p = new Math::BigInt('0x' . unpack('H*', pack('C*', @p_bytes)));
	my $g = new Math::BigInt('0x' . unpack('H*', pack('C*', @g_bytes)));

	my $nonce_limit = new Math::BigInt(1);
	$nonce_limit->blsft(128);

	# Get random bytes that constitute a large exponent for the random number
	# exchange we do.
	my $Ra_binary = Crypt::CBC->_get_random_bytes(32);
	my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
	undef $Ra_binary;
	DEBUG('$Ra is ', $Ra->as_hex());

	# Ma = g^Ra mod p <- This gives us the "random number" that we hand to
	# the server.
	my $Ma = $g->bmodpow($Ra, $p);
	my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), 32));
	DEBUG('$Ma is ', $Ma->as_hex());
	undef $Ma;
	
	# Send an ID value of 0, followed by our Ma value.
	my $authinfo = pack('na*', 0, $Ma_binary);
	undef $Ma_binary;
	DEBUG('$authinfo is 0x', unpack('H*', $authinfo));
	my $resp = undef;

	# Username is always an empty string with AFP 3.0 and up.
	if (Net::AFP::Versions::CompareByVersionNum($session, 3, 0,
			kFPVerAtLeast)) {
		$username = '';
	}
	my $rc = $session->FPChangePassword(UAMNAME, $username, $authinfo, \$resp);
	undef $authinfo;
	DEBUG('FPChangePassword() completed with result code ', $rc);
	return $rc unless $rc == kFPAuthContinue;

	# Unpack the server response for our perusal.
	my ($ID, $Mb_binary, $message) = unpack('na16a32', $resp);
	my $Mb = new Math::BigInt('0x' . unpack('H*', $Mb_binary));
	undef $Mb_binary;
	DEBUG('$Mb is ', $Mb->as_hex());
	DEBUG('$message is 0x', unpack('H*', $message));

	# K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
	# and decrypt ciphertext for communicating with the server.
	my $K = $Mb->bmodpow($Ra, $p);
	undef $Ra;
	undef $Mb;
	my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), 32));
	DEBUG('$K is ', $K->as_hex());
	undef $K;

	# Set up an encryption context with the key we derived, and decrypt the
	# ciphertext that the server sent back to us.
	my $ctx = new Crypt::CBC( {	'key'				=> $K_binary,
								'cipher'			=> $has_Crypt__CAST5 ? 'CAST5' : 'CAST5_PP',
								'padding'			=> 'null',
								'regenerate_key'	=> 0,
								'prepend_iv'		=> 0,
								'iv'				=> S2CIV } );
	undef $K_binary;
	# Set the "magic" IV that allows us to properly decrypt what the server
	# sends to us.
	#$ctx->set_initialization_vector(S2CIV);
	my $decrypted = $ctx->decrypt($message);
	# HACK ALERT: seems decrypt() likes to drop the trailing null on me :|
	# this line should pad out to the appropriate length, which should
	# avoid this problem...
	$decrypted .= "\0" x (32 - length($decrypted));
	DEBUG('$decrypted is 0x', unpack('H*', $decrypted));
	my ($nonce_binary, $serverSig) = unpack('a16a*', $decrypted);
	undef $decrypted;
	DEBUG('$serverSig is 0x', unpack('H*', $serverSig));
	undef $serverSig;

	# The nonce is a random value that the server sends as a check; we add
	# one to it, and send it back to the server to prove we understand what
	# it's saying.
	my $nonce = new Math::BigInt('0x' . unpack('H*', $nonce_binary));
	undef $nonce_binary;
	DEBUG('$nonce is ', $nonce->as_hex());
	$nonce->badd(1);
	$nonce = $nonce->bmod($nonce_limit);
	DEBUG('$nonce is ', $nonce->as_hex(), " after increment");
	my $newnonce_text = substr($nonce->as_hex(), 2);
	undef $nonce;
	my $authdata = pack('H32a64a64', zeropad($newnonce_text, 32), $newPassword,
			$oldPassword);
	undef $newnonce_text;
	$ctx->set_initialization_vector(C2SIV);
	my $ciphertext = $ctx->encrypt($authdata);
	undef $authdata;
	DEBUG('$ciphertext is 0x', unpack('H*', $ciphertext));

	# Send the response back to the server, and hope we did this right.
	$message = pack('na*', $ID, $ciphertext);
	undef $ciphertext;
	$rc = $session->FPChangePassword(UAMNAME, $username, $message);
	undef $message;
	DEBUG('FPChangePassword() completed with result code ', $rc);
	return $rc;
}

1;
# vim: ts=4
