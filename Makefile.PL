use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Backup::ZFSonAWS',
    AUTHOR           => q{Joel De Jesus <dejesus.joel@e-flamingo.jp>},
    VERSION_FROM     => 'lib/Backup/ZFSonAWS.pm',
    ABSTRACT_FROM    => 'lib/Backup/ZFSonAWS.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        'Crypt::OpenSSL::AES',
        'Digest::SHA',
        'Data::Dumper',
        'Digest::SHA'
    },
    'EXE_FILES' => [
		'scripts/zfsonaws'
	],
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Backup-ZFSonAWS-*' },
);
