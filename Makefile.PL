use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Try::Tiny::XS',
    VERSION_FROM      => 'lib/Try/Tiny/XS.pm',
    ABSTRACT_FROM     => 'lib/Try/Tiny/XS.pm',
    AUTHOR            => 'Vickenty Fesunov <kent@setattr.net>',
    LICENSE           => 'perl',
    LIBS              => [],
    TEST_REQUIRES     => {},
    META_MERGE => {
        "meta-spec" => { version => 2 },
        resources => {
            repository => {
                type => "git",
                url => "https://github.com/vickenty/try-tiny-xs",
                web => "https://github.com/vickenty/try-tiny-xs",
            },
            bugtracker => {
                web => "https://github.com/vickenty/try-tiny-xs/issues",
            },
        },
    },
);
