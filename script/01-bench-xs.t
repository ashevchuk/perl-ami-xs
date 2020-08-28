#!/usr/bin/env perl

use strict;
use warnings;

use EV;
use AMI qw(try_connect to_packet to_packet_o to_packet_oo fields_count ami_connect ami_disconnect);
use Benchmark ':hireswallclock';
use Data::Dumper qw(Dumper);

srand(time());

sub rand_packet {
    my ( $fields, $field_size, $value_size ) = @_;
    return  join "\r\n", map { ref $_ ? join ": ", ( (%{$_})[0], (%{$_})[1] ) : $_ } (
	map { +{ ucfirst ( join '', map { (q(a)..q(z))[rand(26)] } 0 .. rand($field_size)+1 ) => ( join '', map { (q(a)..q(z))[rand(26)] } 1 .. rand($value_size) ) } } 0 .. $fields
    ) => "\r\n";
}

sub packet {
    my ( $size, $max_fields, $max_name, $max_value ) = @_;
    my $packet;
    do { $packet = rand_packet(rand($max_fields)+1, rand($max_name)+1, rand($max_value)+1) } while not length($packet) == $size;
    return $packet;
}

sub parse_packet_pp {
    { map { split /:\s/x, $_, 2 } map { split /\015\012/ox } split /\015\012\015\012/ox, shift }
}

#try_connect("127.0.0.1", "5038", sub { print("\nCONNECTED:|@_|\n") });

my $ami_ctx = ami_connect(EV::default_loop, "127.0.0.1", "5038", sub { print("\nAMI Event:|@_|\n") });

my $packet_size = $ARGV[0] // 512;

printf "Generating %d bytes packet ", $packet_size;

my $packet = packet($packet_size, 64, 64, 64);

my $fields_count = fields_count($packet);

printf "%d fields:\n", $fields_count;

print "-" x 32, "\n", $packet, "-" x 32, "\n";

my $a = to_packet_o($packet);
print Dumper($a);

my $a1 = to_packet_oo($packet);
print Dumper($a1);

my $a2 = to_packet($packet);
print Dumper($a2);
#exit 0;

if ( $packet ) {
    my $count = $ARGV[1] // 1_000_000;
    if (0) {
    printf "XS compjmp parsing %d bytes packet %s times:\n", $packet_size, $count;
    my $t = timeit($count, sub {
	to_packet_o($packet);
    });
    printf
        "\t%d iterations in %.6f seconds (%.2f PPS throughput) = %.2f MiB/s (%.2f Mibit/s) bandwidth in %d bytes packet size test\n",
        $t->iters,
        $t->real,
        $t->iters / $t->real,
        (length($packet) * ($t->iters / $t->real)) / 2**20,
        (length($packet) * ($t->iters / $t->real) * 8) / 2**20,
        length($packet);

    printf "XS jmp parsing %d bytes packet %s times:\n", $packet_size, $count;
    my $t1 = timeit($count, sub {
	to_packet_oo($packet);
    });
    printf
        "\t%d iterations in %.6f seconds (%.2f PPS throughput) = %.2f MiB/s (%.2f Mibit/s) bandwidth in %d bytes packet size test\n",
        $t1->iters,
        $t1->real,
        $t1->iters / $t1->real,
        (length($packet) * ($t1->iters / $t1->real)) / 2**20,
        (length($packet) * ($t1->iters / $t1->real) * 8) / 2**20,
        length($packet);

    printf "XS plain parsing %d bytes packet %s times:\n", $packet_size, $count;
    my $t2 = timeit($count, sub {
	to_packet($packet);
    });
    printf
        "\t%d iterations in %.6f seconds (%.2f PPS throughput) = %.2f MiB/s (%.2f Mibit/s) bandwidth in %d bytes packet size test\n",
        $t2->iters,
        $t2->real,
        $t2->iters / $t2->real,
        (length($packet) * ($t2->iters / $t2->real)) / 2**20,
        (length($packet) * ($t2->iters / $t2->real) * 8) / 2**20,
        length($packet);

    printf "XS counting fields in %d bytes packet %s times:\n", $packet_size, $count;
    my $t3 = timeit($count, sub {
	fields_count($packet);
    });
    printf
        "\t%d iterations in %.6f seconds (%.2f PPS throughput) = %.2f MiB/s (%.2f Mibit/s) bandwidth in %d bytes packet size test\n",
        $t3->iters,
        $t3->real,
        $t3->iters / $t3->real,
        (length($packet) * ($t3->iters / $t3->real)) / 2**20,
        (length($packet) * ($t3->iters / $t3->real) * 8) / 2**20,
        length($packet);

    }
} else {
    die "invalid packet: $packet";
}

EV::run;

ami_disconnect($ami_ctx);
