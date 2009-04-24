# This package fairly correctly implements the DHX (aka DHCAST128) User
# Authentication Method for AFP sessions. It uses a Diffie-Hellman key
# exchange to establish a keyset that can be used for (reasonably) secure
# password-based authentication without the need for prehashed passwords.
# It requires the Crypt::CBC module to provide a cipher-block-chaining
# layer, and Crypt::CAST5 to provide the CAST5 (aka CAST128) encryption
# method used to secure the data over the wire. Math::BigInt::GMP is
# recommended for fast large-integer operations, as Math::BigInt::Calc
# works but is quite slow.

package Net::AFP::UAMs::DHX;
use constant UAMNAME => 'DHCAST128';

use constant C2SIV => 'LWallace';
use constant S2CIV => 'CJalbert';

# Provides the encryption algorithm.
use Crypt::CAST5;
# Provides the cipher-block chaining layer over the encryption algorithm.
use Crypt::CBC;
# Used to read from /dev/urandom for originating random data for the
# cryptographic exchanges.
use IO::File;
# Pull in the module containing all the result code symbols.
use Net::AFP::Result;
# Provides large-integer mathematics features, necessary for the
# cryptographic exchanges and derivation of the key. Fast, but the
# non-threaded to threaded changeover hoses it, so don't create Math::BigInt
# objects until after threads are started.
use Math::BigInt lib => 'GMP';
use strict;
use warnings;

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
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	die('Password callback MUST be a subroutine ref')
			unless ref($pw_cb) eq 'CODE';

	# Moving these into the functions, to make Math::BigInt::GMP happy.
	my $p = new Math::BigInt('0x' . unpack('H*', pack('C*', @p_bytes)));
	my $g = new Math::BigInt('0x' . unpack('H*', pack('C*', @g_bytes)));

	my $nonce_limit = new Math::BigInt(1);
	$nonce_limit->blsft(128);

	# Get random bytes that constitute a large exponent for the random number
	# exchange we do.
	my $randsrc = new IO::File('/dev/urandom', 'r');
	my $Ra_binary = '';
	die('Random source problem!') unless read($randsrc, $Ra_binary, 32) == 32;
	my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
	undef $Ra_binary;
	print '$Ra is ', $Ra->as_hex(), "\n" if defined $::__AFP_DEBUG;

	# Ma = g^Ra mod p <- This gives us the "random number" that we hand to
	# the server.
	my $Ma = $g->bmodpow($Ra, $p);
	my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), 32));
	print '$Ma is ', $Ma->as_hex(), "\n" if defined $::__AFP_DEBUG;
	undef $Ma;
	
	# Send the "random number" to the server as the first stage of the
	# authentication process, along with the username.
	my $authinfo = pack('C/a*x![s]a*', $username, $Ma_binary);
	print '$authinfo is 0x', unpack('H*', $authinfo), "\n"
			if defined $::__AFP_DEBUG;
	my $resp = undef;
	my $rc = $session->FPLoginExt(0, $AFPVersion, UAMNAME, 3, $username, 3, '',
			$Ma_binary, \$resp);
	print 'FPLoginExt() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;

	# Fall back to FPLogin if the server says it doesn't know what we're
	# talking about.
	if ($rc == Net::AFP::Result::kFPCallNotSupported) {
		my $authinfo = pack('C/a*x![s]a*', $username, $Ma_binary);
		$rc = $session->FPLogin($AFPVersion, UAMNAME, $authinfo, \$resp);
		print 'FPLogin() completed with result code ', $rc, "\n"
				if defined $::__AFP_DEBUG;
	}
	undef $Ma_binary;
	undef $authinfo;
	return $rc unless $rc == Net::AFP::Result::kFPAuthContinue;
	my ($Mb_binary, $message) = unpack('a16a*', $resp->{'UserAuthInfo'});
	my $Mb = new Math::BigInt('0x' . unpack('H*', $Mb_binary));
	undef $Mb_binary;
	print '$Mb is ', $Mb->as_hex(), "\n" if defined $::__AFP_DEBUG;
	print '$message is 0x', unpack('H*', $message), "\n"
			if defined $::__AFP_DEBUG;

	# K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
	# and decrypt ciphertext for communicating with the server.
	my $K = $Mb->bmodpow($Ra, $p);
	undef $Ra;
	undef $Mb;
	my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), 32));
	print '$K is ', $K->as_hex(), "\n" if defined $::__AFP_DEBUG;
	undef $K;

	# Set up an encryption context with the key we derived, and decrypt the
	# ciphertext that the server sent back to us.

	# NOTE NOTE NOTE: If this UAM breaks, see the docs for Crypt::CBC.
	# Its developer thinks it's a great idea to keep adding parameters
	# which then break expected behavior for those coding against it.
	# This code is PERFECT. It is 100% in line with Apple's docs.
	my $ctx = new Crypt::CBC( {	'key'				=> $K_binary,
								'cipher'			=> 'CAST5',
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
	print '$decrypted is 0x', unpack('H*', $decrypted), "\n"
			if defined $::__AFP_DEBUG;
	my ($nonce_binary, $serverSig) = unpack('a16a*', $decrypted);
	undef $decrypted;
	print '$serverSig is 0x', unpack('H*', $serverSig), "\n"
			if defined $::__AFP_DEBUG;
	undef $serverSig;

	# The nonce is a random value that the server sends as a check; we add
	# one to it, and send it back to the server to prove we understand what
	# it's saying.
	my $nonce = new Math::BigInt('0x' . unpack('H*', $nonce_binary));
	undef $nonce_binary;
	print '$nonce is ', $nonce->as_hex(), "\n" if defined $::__AFP_DEBUG;
	$nonce->badd(1);
	$nonce = $nonce->bmod($nonce_limit);
	print '$nonce is ', $nonce->as_hex(), " after increment\n"
			if defined $::__AFP_DEBUG;
	my $newnonce_text = substr($nonce->as_hex(), 2);
	undef $nonce;
	my $authdata = pack('H*a64', zeropad($newnonce_text, 32), &$pw_cb());
	undef $newnonce_text;
	$ctx->set_initialization_vector(C2SIV);
	my $ciphertext = $ctx->encrypt($authdata);
	undef $authdata;
	print '$ciphertext is 0x', unpack('H*', $ciphertext), "\n"
			if defined $::__AFP_DEBUG;

	# Send the response back to the server, and hope we did this right.
	$rc = $session->FPLoginCont($resp->{'ID'}, $ciphertext);
	undef $ciphertext;
	print 'FPLoginCont() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;
	return $rc;
}

sub ChangePassword {
	my($session, $username, $oldPassword, $newPassword) = @_;

	# Ensure that we've been handed an appropriate object.
	die('Object MUST be of type Net::AFP::Connection!')
			unless ref($session) ne '' and $session->isa('Net::AFP::Connection');

	# Moving these into the functions, to make Math::BigInt::GMP happy.
	my $p = new Math::BigInt('0x' . unpack('H*', pack('C*', @p_bytes)));
	my $g = new Math::BigInt('0x' . unpack('H*', pack('C*', @g_bytes)));

	my $nonce_limit = new Math::BigInt(1);
	$nonce_limit->blsft(128);

	# Get random bytes that constitute a large exponent for the random number
	# exchange we do.
	my $randsrc = new IO::File('/dev/urandom', 'r');
	my $Ra_binary = '';
	die('Random source problem!') unless read($randsrc, $Ra_binary, 32) == 32;
	my $Ra = new Math::BigInt('0x' . unpack('H*', $Ra_binary));
	undef $Ra_binary;
	print '$Ra is ', $Ra->as_hex(), "\n" if defined $::__AFP_DEBUG;

	# Ma = g^Ra mod p <- This gives us the "random number" that we hand to
	# the server.
	my $Ma = $g->bmodpow($Ra, $p);
	my $Ma_binary = pack('H*', zeropad(substr($Ma->as_hex(), 2), 32));
	print '$Ma is ', $Ma->as_hex(), "\n" if defined $::__AFP_DEBUG;
	undef $Ma;
	
	# Send an ID value of 0, followed by our Ma value.
	my $authinfo = pack('na*', 0, $Ma_binary);
	undef $Ma_binary;
	print '$authinfo is 0x', unpack('H*', $authinfo), "\n"
			if defined $::__AFP_DEBUG;
	my $resp = undef;
	# FIXME: We'll have to do this the right way for pre-AFP 3.0 stacks.
	# The docs say that 3.0 and up expect an empty username.
	my $rc = $session->FPChangePassword(UAMNAME, '', $authinfo, \$resp);
	undef $authinfo;
	print 'FPChangePassword() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;
	return $rc unless $rc == Net::AFP::Result::kFPAuthContinue;

	# Unpack the server response for our perusal.
	my ($ID, $Mb_binary, $message) = unpack('na16a32', $resp);
	my $Mb = new Math::BigInt('0x' . unpack('H*', $Mb_binary));
	undef $Mb_binary;
	print '$Mb is ', $Mb->as_hex(), "\n" if defined $::__AFP_DEBUG;
	print '$message is 0x', unpack('H*', $message), "\n"
			if defined $::__AFP_DEBUG;

	# K = Mb^Ra mod p <- This nets us the key value that we use to encrypt
	# and decrypt ciphertext for communicating with the server.
	my $K = $Mb->bmodpow($Ra, $p);
	undef $Ra;
	undef $Mb;
	my $K_binary = pack('H*', zeropad(substr($K->as_hex(), 2), 32));
	print '$K is ', $K->as_hex(), "\n" if defined $::__AFP_DEBUG;
	undef $K;

	# Set up an encryption context with the key we derived, and decrypt the
	# ciphertext that the server sent back to us.
	my $ctx = new Crypt::CBC( {	'key'				=> $K_binary,
								'cipher'			=> 'CAST5',
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
	print '$decrypted is 0x', unpack('H*', $decrypted), "\n"
			if defined $::__AFP_DEBUG;
	my ($nonce_binary, $serverSig) = unpack('a16a*', $decrypted);
	undef $decrypted;
	print '$serverSig is 0x', unpack('H*', $serverSig), "\n"
			if defined $::__AFP_DEBUG;
	undef $serverSig;

	# The nonce is a random value that the server sends as a check; we add
	# one to it, and send it back to the server to prove we understand what
	# it's saying.
	my $nonce = new Math::BigInt('0x' . unpack('H*', $nonce_binary));
	undef $nonce_binary;
	print '$nonce is ', $nonce->as_hex(), "\n" if defined $::__AFP_DEBUG;
	$nonce->badd(1);
	$nonce = $nonce->bmod($nonce_limit);
	print '$nonce is ', $nonce->as_hex(), " after increment\n"
			if defined $::__AFP_DEBUG;
	my $newnonce_text = substr($nonce->as_hex(), 2);
	undef $nonce;
	my $authdata = pack('H32a64a64', zeropad($newnonce_text, 32), $oldPassword,
			$newPassword);
	undef $newnonce_text;
	$ctx->set_initialization_vector(C2SIV);
	my $ciphertext = $ctx->encrypt($authdata);
	undef $authdata;
	print '$ciphertext is 0x', unpack('H*', $ciphertext), "\n"
			if defined $::__AFP_DEBUG;

	# Send the response back to the server, and hope we did this right.
	# FIXME: We'll have to do this the right way for pre-AFP 3.0 stacks.
	# The docs say that 3.0 and up expect an empty username.
	$message = pack('na*', $ID, $ciphertext);
	undef $ciphertext;
	$rc = $session->FPChangePassword(UAMNAME, '', $message);
	undef $message;
	print 'FPChangePassword() completed with result code ', $rc, "\n"
			if defined $::__AFP_DEBUG;
	return $rc;
}

1;
# vim: ts=4
