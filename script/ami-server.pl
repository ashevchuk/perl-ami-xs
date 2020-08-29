#!/usr/bin/env perl

use strict;
use warnings;

use constant {
    ADDR  => undef,
    DEBUG => 0,
    PORT  => 5038,
    TIME  => '%F %T'
};

use EV;

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Data::Dumper qw(Dumper);
use Time::HiRes;

use POSIX;
use Socket;

sub stime {
    my ( $sec, $usec ) = Time::HiRes::gettimeofday();
    return POSIX::strftime( "%F %T" . sprintf( ".%06d", $usec ),
        localtime($sec) );
}

sub print_packet {
    my ( $dir, $dst, @fields ) = @_;
    my @packet;
    do { push @packet, sprintf( "\t%s: %s", shift(@fields), shift(@fields) ) }
      while scalar @fields;
    my $packet = join( "\n", @packet );
    my $size = length($packet) - 1;
    printf(
        "\n" . $dir x 3 . " %s " . $dir x 1 . " %s (%d bytes)\n%s\n" . $dir x 32 . "\n",
        stime(), $dst, $size, $packet );
}

sub rand_packet {
    my ( $fields, $field_size, $value_size ) = @_;
    return join "\r\n",
      map { ref $_ ? join ": ", ( ( %{$_} )[0], ( %{$_} )[1] ) : $_ } (
        {
            Event => (
                join '', map { ( q(a) .. q(z) )[ rand(26) ] } 1 .. $value_size
            )
        },
        map {
            +{
                ucfirst(
                    join '',
                    map { ( q(a) .. q(z) )[ rand(26) ] }
                      0 .. rand($field_size) + 1
                ) => (
                    join '',
                    map { ( q(a) .. q(z) )[ rand(26) ] } 1 .. rand($value_size)
                )
            }
        } 0 .. $fields
      );
}

sub packet {
    my ( $size, $max_fields, $max_name, $max_value ) = @_;
    my $packet;
    do {
        $packet = rand_packet(
            rand($max_fields) + 1,
            rand($max_name) + 1,
            rand($max_value) + 1
        );
    } while not length($packet) == $size;
    return $packet;
}

sub parse_packet {
    my ($packet) = @_;
    $packet .= "\r\n";
    return map { split /:\s/x, $_, 2 } map { split /\015\012/ox } $packet;
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

sub ami_send {
    my ( $hdl, @fields ) = @_;

    my $response = as_packet(@fields);

    $hdl->push_write($response);

    if ( defined $hdl ) {
        if ( my $peer = getpeername( $hdl->fh() ) ) {
                my ( $port, $host ) = Socket::unpack_sockaddr_in( $peer );
                print_packet( '>', Socket::inet_ntoa($host) . ":" . $port, @fields )
                  if DEBUG;
        }
    }
}

my $packet_size                = $ARGV[0] // 512;
my $events_interval            = $ARGV[1] // 0.0001;
my $events_regenerate_interval = $ARGV[2] // 10;

my @event_packet;
my %connections;

my $events_regenerate_timer = AnyEvent->timer(
    (
        $events_regenerate_interval
        ? ( interval => $events_regenerate_interval )
        : ()
    ),
    after => 0,
    cb    => sub {
        @event_packet = parse_packet( packet( $packet_size, 16, 16, 64 ) );
#        print_packet( '=', "Generated packet", @event_packet ) if DEBUG;
    }
);

AnyEvent::Socket::tcp_server(
    ADDR, PORT,
    sub {
        my ( $fh, $host, $port ) = @_;

        printf( "\n=== %s = AMI client (%s:%s) connected\n",
            stime(), $host, $port )
          if DEBUG;

        my $handle;
        $handle = AnyEvent::Handle->new(
            fh       => $fh,
            on_error => sub {
                printf( "\n=== %s = AMI client (%s:%s) error: %s\n",
                    stime(), $host, $port, $_[2] )
                  if DEBUG;
                undef $_[0]->{send_timer} if exists $_[0]->{send_timer};
                $_[0]->destroy;
            },
            on_eof => sub {
                undef $handle->{send_timer} if exists $handle->{send_timer};
                $handle->destroy;
                printf( "\n=== %s = AMI client (%s:%s) disconnected\n",
                    stime(), $host, $port )
                  if DEBUG;
            }
        );

        $handle->push_write("Asterisk Call Manager/2.10.4\r\n");

        $handle->on_read(
            sub {
                my ($hdl) = @_;
                $hdl->push_read(
                    line => "\r\n\r\n",
                    sub {
                        my ( $hdl, $packet ) = @_;

                        my @request = parse_packet($packet);

                        print_packet( '<', "$host:$port", @request ) if DEBUG;

                        if ( exists {@request}->{Action} ) {
                            if ( lc( {@request}->{Action} ) eq "login" ) {
                                ami_send(
                                    $hdl,
                                    Response => 'Success',
                                    ActionID => {@request}->{ActionID},
                                    Message  => 'Authentication accepted'
                                );

                                ami_send(
                                    $hdl,
                                    Event     => 'FullyBooted',
                                    Privilege => 'system,all',
                                    Status    => 'Fully Booted'
                                );

                                $hdl->{send_timer} = AnyEvent->timer(
                                    after    => 5,
                                    interval => $events_interval,
                                    cb       => sub {
                                        ami_send( $hdl, @event_packet );
                                    }
                                );
                            }
                            elsif ( lc( {@request}->{Action} ) eq "ping" ) {
                                ami_send(
                                    $hdl,
                                    Response  => 'Success',
                                    ActionID  => {@request}->{ActionID},
                                    Ping      => 'Pong',
                                    Timestamp => Time::HiRes::time()
                                );
                            }
                            else {
                                ami_send(
                                    $hdl,
                                    Response => 'Success',
                                    @request
                                );
                            }
                        }
                        0;
                    }
                );
            }
        );
    },
    sub {
        my ($fh) = @_;
        15;
    }
);

EV::loop;
