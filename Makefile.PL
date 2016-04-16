#!/usr/bin/env perl

use ExtUtils::MakeMaker;
WriteMakefile(
	'NAME'		=> 'Net::AFP',
	'VERSION_FROM'	=> 'lib/Net/AFP.pm',
	'EXE_FILES'	=>  [
        'examples/afp_acl.pl',
        'examples/afpmount.pl',
        'examples/afpclient.pl',
    ],
    'PREREQ_PM' => {
        'Log::Log4perl'     => 0,
        'Log::Dispatch'     => 0,
        'Fuse'              => '0.12',
        'Fuse::Class'       => 0,
#        'Data::UUID'        => undef,
        'Crypt::CBC'        => 0,
#        'Math::BigInt::GMP' => 0,
        'Term::ReadPassword' => 0,
        'URI::Escape'       => 0,
    },
);
