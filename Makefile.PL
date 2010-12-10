#!/usr/bin/env perl

use ExtUtils::MakeMaker;
WriteMakefile(
	'NAME'		=> 'Net::AFP',
	'VERSION_FROM'	=> 'lib/Net/AFP.pm',
	'EXE_FILES'	=>  [ 'examples/afp_acl.pl', 'examples/afpmount.pl', 'examples/afpsh.pl' ],
);
