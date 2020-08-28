#!/usr/bin/env perl

use strict;
use warnings;

use EV;
use AMI qw(try_connect to_packet to_packet_o to_packet_oo fields_count ami_connect ami_write ami_disconnect);
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

sub as_packet {
    my (@fields) = @_;

    return warn "Invalid fields" if scalar(@fields) % 2;

    my @packet;

    do {
	my $field = shift @fields;
	my $value = shift @fields;
	push @packet, sprintf( "%s: %s", $field, $value );
    } while scalar @fields;

    return join "\r\n", ( @packet, "\r\n" );
}

my $ami_ctx = ami_connect(EV::default_loop, "127.0.0.1", "5038", sub { print("\nAMI Event:|@_|\n") });

ami_write($ami_ctx, as_packet(
    Action => 'Login',
    ActionID => 1,
    Username => 'manager-wwbprv',
    Secret => 'tASofV5vlU4m',
    Events => 'on'
));

EV::run;

#ami_disconnect($ami_ctx);
#undef $ami_ctx;

