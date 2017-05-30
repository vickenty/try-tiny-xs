use strict;
use warnings;
use Test::More;

use Try::Tiny::XS;

my $called;
my $caught;

try {
    $called = 1;
    die "test\n";
} catch {
    $caught = $_;
};

is $called, 1, "try works";
is $caught, "test\n", "catch works";

done_testing;
