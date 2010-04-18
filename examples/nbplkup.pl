#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use Net::Atalk::NBP;
use Getopt::Long;

my $maxents;
my $localaddr;

sub usage {
	print "Usage:\t", $0, " [ -A address ] [ -r responses ] [ obj:type\@zone ]\n";
	exit(1);
}

GetOptions('A=s' => \$localaddr,
		   'r=i' => \$maxents) || usage();

my ($type, $zone);

usage() if scalar(@ARGV) > 1;
my ($host) = @ARGV;
if (defined $host) {
	my ($type, $zone) = $host =~ s/(?::(\w+|=))?(?:\@(\w+|\*))?$//;
	($type, $zone) = ($1, $2);
}

foreach my $tuple (NBPLookup($host, $type, $zone, $localaddr, $maxents)) {
	printf("\%31s:\%-32s \%9s:\%-3d\n", @$tuple[3,4,0,1]);
}
