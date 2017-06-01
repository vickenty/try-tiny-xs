package Try::Tiny::XS 0.01;
use strict;
use warnings;
use XSLoader;

sub import {
    $^H{"Try::Tiny::XS/enabled"} = 1;
}

sub invoke_catch {
    for ($_[1]) {
        return $_[0]->($_[1]);
    }
    return;
}

XSLoader::load();

1;
