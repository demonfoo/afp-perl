#!/usr/bin/env perl

use strict;
use warnings;

use Net::Bonjour;
use Net::AFP::TCP;
use Data::Dumper;

my $has_atalk = 0;
eval {
	require Net::Atalk::NBP;
	require Net::AFP::Atalk;
} and do {
    Net::Atalk::NBP->import();
    Net::AFP::Atalk->import();
	$has_atalk = 1;
};

my $mdns = new Net::Bonjour('afpovertcp', 'tcp');
$mdns->discover();

foreach my $entry ($mdns->entries()) {
	print 'For host ', $entry->name(), ":\n";
	my $srvInfo;
	my $rc = Net::AFP::TCP->GetStatus($entry->address(), $entry->port(),
            \$srvInfo);
	print Dumper($srvInfo);
}

if (not $has_atalk) {
    exit(0);
}

my @results;
eval {
	@results = NBPLookup(undef, 'AFPServer');
};

foreach my $entry (@results) {
	print 'For host ', $entry->[3], ":\n";
	my $srvInfo;
	my $rc = Net::AFP::Atalk->GetStatus($entry->[0], $entry->[1], \$srvInfo);
	print Dumper($srvInfo);
}
