use 5.014002;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Backup::ZFSonAWS',
    AUTHOR           => q{Joel DeJesus (Work email) <dejesus.joel@e-flamingo.jp>},
    VERSION_FROM     => 'lib/Backup/ZFSonAWS.pm',
    ABSTRACT_FROM    => 'lib/Backup/ZFSonAWS.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    #MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        'Crypt::OpenSSL::AES' => 0,
        'Digest::SHA' => 0,
        'Data::Dumper' => 0,
        'Digest::SHA' => 0,
        'JSON::XS' => 0
    },
    'EXE_FILES' => [
		'scripts/zfsonaws'
	],
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Backup-ZFSonAWS-*' }
);
sub MY::makefile { 
	return << "EOF";
INST_ETC        = blib/etc
DESTINSTALLETC = \$(DESTDIR)/etc
# This target is used by both CPAN and Debian builds
config::
        $(MKPATH) $(INST_ETC)
 
# This target is used by both CPAN and Debian builds
pure_all::
	$(CP) -r etc/* $(INST_ETC)
 
# This target is used only by CPAN builds; Debian uses debian/conffiles
pure_install:: all
        $(MKPATH) $(DESTINSTALLETC)/$(NAME)
        $(CP) -r $(INST_ETC)/* $(DESTINSTALLETC)/$(NAME)
EOF

 }


