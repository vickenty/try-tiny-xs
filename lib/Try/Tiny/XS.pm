package Try::Tiny::XS 0.01;
use strict;
use warnings;
use XSLoader;

require Try::Tiny;
require Exporter;

our @EXPORT = qw/try catch finally/;
our @EXPORT_OK = @EXPORT;

sub import {
    $^H{"Try::Tiny::XS/enabled"} = 1 if $ENV{TTXS_USE_KEYWORD} // 1;
    goto &Exporter::import;
}

sub invoke_catch {
    for ($_[1]) {
        return ${$_[0]}->($_[1]);
    }
    return;
}

sub try(&;@) {
    goto &Try::Tiny::try;
}

sub catch(&;@) {
    my $block = shift;
    return (bless($block, "Try::Tiny::XS::Catch"), @_);
}

sub finally(&;@) {
    my $block = shift;
    return (bless($block, "Try::Tiny::XS::Finally"), @_);
}

XSLoader::load();

1;
