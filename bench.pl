use strict;
use warnings;
use Dumbbench;

require Try::Tiny;
require Try::Tiny::XS;

sub bench_ev {
    my $die = shift;
    my $x = 0;
    foreach my $c (0..100000) {
        eval {
            $die and die "oh well";
            1;
        } or do {
            my $err = $@;
            $x++;
        };
    }
}

sub bench_pp {
    my $die = shift;
    my $x = 0;
    foreach my $c (0..100000) {
        Try::Tiny::try(sub {
            $die and die "oh well";
        }, Try::Tiny::catch(sub {
            $x++;
        }));
    }
}

sub bench_xs {
    my $die = shift;
    my $x = 0;
    foreach my $c (0..100000) {
        Try::Tiny::XS::try(sub {
            $die and die "oh well";
        }, Try::Tiny::XS::catch(sub {
            $x++;
        }));
    }
}

my $bench = Dumbbench->new(
    target_rel_precision => 0.05,
    initial_runs => 20,
);

$bench->add_instances(
    Dumbbench::Instance::PerlSub->new(name => "pp 0", code => sub { bench_pp 0 }),
    Dumbbench::Instance::PerlSub->new(name => "xs 0", code => sub { bench_xs 0 }),
    Dumbbench::Instance::PerlSub->new(name => "ev 0", code => sub { bench_ev 0 }),
    Dumbbench::Instance::PerlSub->new(name => "pp 1", code => sub { bench_pp 1 }),
    Dumbbench::Instance::PerlSub->new(name => "xs 1", code => sub { bench_xs 1 }),
    Dumbbench::Instance::PerlSub->new(name => "ev 1", code => sub { bench_ev 1 }),
);

$bench->run;
$bench->report;
