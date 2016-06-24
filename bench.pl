use strict;
use warnings;
use Dumbbench;

require Try::Tiny;
require Try::Tiny::XS;

sub bench_ev {
    my $x = 0;
    foreach my $c (0..100000) {
        eval {
            die "oh well";
            1;
        } or do {
            my $err = $@;
            $x++;
        };
    }
}

sub bench_pp {
    my $x = 0;
    foreach my $c (0..100000) {
        Try::Tiny::try(sub {
            die "oh well";
        }, Try::Tiny::catch(sub {
            $x++;
        }));
    }
}

sub bench_xs {
    my $x = 0;
    foreach my $c (0..100000) {
        Try::Tiny::XS::try(sub {
            die "oh well";
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
    Dumbbench::Instance::PerlSub->new(name => "pp", code => \&bench_pp),
    Dumbbench::Instance::PerlSub->new(name => "xs", code => \&bench_xs),
    Dumbbench::Instance::PerlSub->new(name => "ev", code => \&bench_ev),
);

$bench->run;
$bench->report;
