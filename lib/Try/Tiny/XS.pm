package Try::Tiny::XS 0.01;
use strict;
use warnings;
use XSLoader;
use Exporter "import";
use Try::Tiny qw/catch finally/;

our @EXPORT = qw/try catch finally/;

XSLoader::load();

1;
