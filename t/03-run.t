use Test::More tests => 2;
BEGIN { use_ok('AMI', qw(to_packet to_packet_o to_packet_oo)) };

my $packet = join "\r\n", map { ref $_ ? join ": ", ( (%{$_})[0], (%{$_})[1] ) : $_ } (
    map { +{ ucfirst ( join '', map { (q(a)..q(z))[rand(26)] } 0 .. rand(16)+1 ) => ( join '', map { (q(a)..q(z))[rand(26)] } 1 .. rand(64) ) } } 0 .. 16
) => "\r\n";

is_deeply( { map { split /:\s/x, $_, 2 } map { split /\015\012/ox } split /\015\012\015\012/ox, $packet }, to_packet( $packet ) );
