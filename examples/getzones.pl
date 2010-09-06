#!/usr/bin/env perl

use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

use strict;
use warnings;
use diagnostics;

use Net::Atalk::ZIP;
use Getopt::Long;

sub usage {
	print STDERR "usage:\t", $0, " [-m | -l] [address]\n";
	exit(1);
}

my $zipcall = \&ZIPGetZoneList;
my ($myzoneflag, $localzonesflag);
GetOptions( 'm'	=> sub {
			usage() if defined $localzonesflag;
			$zipcall = \&ZIPGetMyZone;
			$myzoneflag = 1;
		},
			'l'	=> sub {
			usage() if defined $myzoneflag;
			$zipcall = \&ZIPGetLocalZones;
			$localzonesflag = 1;
		},
			'h' => \&usage ) || usage();

my ($zonelist, $lastflag) = &$zipcall($ARGV[0], 0);
die('Error sending ZIP request: ' . $!) unless $zonelist;
if (ref($zonelist) eq 'ARRAY') {
	foreach (@$zonelist) { print $_, "\n" }
} else {
	print $zonelist, "\n";
}
