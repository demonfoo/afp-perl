package Net::AFP::UAMs;

use Net::AFP::TokenTypes;
use Net::AFP::Result;

=head1 NAME

Net::AFP::UAMs - AFP authentication helper functions

=head1 DESCRIPTION

This package contains convenience functions for calling User
Authentication Method code on an AFP connection.

=cut

# Try to import classes for the password based auth methods. If they can't
# be imported, it probably means they have dependencies that can't be
# fulfilled.

my @UAMReg = ();

# uamname is the string (case insensitive) which the server knows the UAM by.
# class is the class name containing an Authenticate method which can be
# used to authenticate to an AFP server that knows the UAM. preference is an
# integer used to indicate what order the UAMs should be chosen in by the
# client. a preference of less than 0 means the UAM will never be selected
# automatically.
sub RegisterUAM {
	my ($uamname, $class, $pref) = @_;

	my $uaminfo = { 'name' => $uamname, 'class' => $class, 'pref' => $pref };
	for (my $i = 0; $i <= $#UAMReg; $i++) {
		next if $UAMReg[$i]->{'pref'} > $pref;
		@UAMReg = (@UAMReg[0 .. ($i - 1)], $uaminfo, @UAMReg[$i .. $#UAMReg]);
		return;
	}
	push(@UAMReg, $uaminfo);
}

# Find the UAM includes, and assemble a list of them.
my @uampaths = ();
foreach my $incpath (@INC) {
	my $uamincpath = $incpath . '/Net/AFP/UAMs';
	if (-d $uamincpath) {
		opendir(UAMDIR, $uamincpath);
		push(@uampaths, map { $uamincpath . '/' . $_ } grep(/\.pm$/, readdir(UAMDIR)));
		closedir(UAMDIR);
	}
}

# Try including each of them via eval, so that if they explode, it won't
# impair our ability to continue on.
foreach my $uampath (@uampaths) {
	eval { require $uampath; };
	if ($@) {
		print STDERR 'Couldn\'t include ', $uampath, ":\n";
		print STDERR '-' x 15, ' start error text ', '-' x 15, "\n", $@;
		print STDERR '-' x 16, ' end error text ', '-' x 16, "\n";
		print STDERR "This error is not fatal; other UAMs will be tried.\n\n";
	}
}

=head1 FUNCTIONS

=over

=item GuestAuth()

Perform simple anonymous (guest) authentication with the server.

=over

=item $session

=item $AFPVersion

=back

=cut
sub GuestAuth($$) {
	my($session, $AFPVersion) = @_;
	my $rc = Net::AFP::UAMs::Anonymous::Authenticate($session, $AFPVersion);
	if ($rc == kFPNoErr) {
		$$session{'AFPVersion'} = $AFPVersion;
	}
	return $rc;
}

=item PasswordAuth()

Perform password-based authentication with the server.

=over

=item $session

=item $AFPVersion

=item $SupportedUAMs

=item $UserName

=item $PwCallback

=back

=cut
sub PasswordAuth($$$$$) {
	my($session, $AFPVersion, $SupportedUAMs, $UserName, $PwCallback) = @_;
#	die('Need a function ref for password callback')
#			unless ref($PwCallback) eq 'CODE';

	# The AFP server often sets a really lousy UAM order; I should really
	# have a prioritized list of UAMs that we know are good, and try to
	# use the best ones first. OS 9.x likes to specify cleartext auth at
	# the top of the list... not so great.
	my %ReqUAMs = map { lc($_), 1 } @$SupportedUAMs;
	foreach my $uaminfo (@UAMReg) {
		next unless exists $ReqUAMs{lc($$uaminfo{'name'})};
		last if $$uaminfo{'pref'} < 0 and scalar(keys %ReqUAMs) > 1;
		my $function = $$uaminfo{'class'} . '::Authenticate';
		print 'auth function is ', $function, "\n" if defined $::__AFP_DEBUG;
		$session->{'username'} = $UserName;
		my $rc = &{$function}($session, $AFPVersion, $UserName, $PwCallback);
		if ($rc == kFPNoErr) {
			$$session{'AFPVersion'} = $AFPVersion;
		}
		return $rc;
	}

	# If we reach this point, none of the UAMs the server knew were available.
	print "", (caller(0))[3], 
			" Could not find an agreeable UAM for authenticating to server\n"
			if defined $::__AFP_DEBUG;
	return kFPBadUAM;
}

=back

=cut

1;
# vim: ts=4
