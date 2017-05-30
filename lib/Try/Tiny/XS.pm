package Try::Tiny::XS 0.01;
use strict;
use warnings;
use XSLoader;

sub import {
    $^H{"Try::Tiny::XS/enabled"} = 1;
}

XSLoader::load();

1;
