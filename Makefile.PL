#!/usr/bin/env perl

use ExtUtils::MakeMaker;
WriteMakefile(
    NAME            => 'Net::AFP',
    VERSION_FROM    => 'lib/Net/AFP.pm',
    EXE_FILES       => [
        'examples/afp_acl.pl',
        'examples/afpmount.pl',
        'examples/afpclient.pl',
    ],
    PREREQ_PM => {
        'Log::Log4perl'         => 0,
        'Log::Dispatch'         => 0,
        'Fuse'                  => '0.12',
        'Fuse::Class'           => 0,
        'URI::Escape'           => 0,
        'Readonly'              => 0,
        'Class::InsideOut'      => 0,
        'String::Escape'        => 0,
        'Term::ReadLine'        => 0,
        'Text::Glob'            => 0,
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        prereqs   => {
            runtime => {
                recommends => {
                    'CryptX'                => 0,
                    'UUID'                  => 0,
                    'PerlIO::buffersize'    => 0,
                    'Term::ReadPassword'    => 0,
                    'IO::Socket::IP'        => 0,
                },
                'suggests' => {
                    'Net::Atalk'            => 0,
                    'Term::ReadLine::Gnu'   => 0,
                    'Term::ReadLine::Perl5' => 0,
                    'Term::ReadKey'         => 0,
                    'Net::Bonjour'          => 0,
                    'Archive::Tar'          => 0,
                },
            },
        },
    },
);
