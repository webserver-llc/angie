#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Stream tests for upstream least_conn balancer module with datagrams.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ dgram /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_upstream_least_conn udp/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    proxy_responses      1;
    proxy_timeout        1s;

    upstream u {
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    server {
        listen      127.0.0.1:8080 udp;
        proxy_pass  u;
    }
}

EOF

$t->run_daemon(\&udp_daemon, 8081, $t);
$t->run_daemon(\&udp_daemon, 8082, $t);
$t->try_run('no stream udp')->plan(2);

$t->waitforfile($t->testdir . '/8081');
$t->waitforfile($t->testdir . '/8082');

###############################################################################

is(many('.', 10), '8081: 5, 8082: 5', 'balanced');

my @sockets;
for (1 .. 2) {
	my $s = dgram();
	$s->write('w');
	push @sockets, $s;
}

select undef, undef, undef, 0.2;

is(many('.', 10), '8082: 10', 'least_conn');

###############################################################################

sub many {
	my ($data, $count, %opts) = @_;
	my (%ports);

	for (1 .. $count) {
		if (dgram()->io($data) =~ /(\d+)/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	return join ', ', map { $_ . ": " . $ports{$_} } sort keys %ports;
}

###############################################################################

sub udp_daemon {
	my ($port, $t) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'udp',
		LocalAddr => '127.0.0.1:' . $port,
		Reuse => 1,
	)
		or die "Can't create listening socket: $!\n";

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (1) {
		$server->recv(my $buffer, 65536);

		my $port = $server->sockport();

		if ($buffer =~ /w/ && $port == 8081) {
			select undef, undef, undef, 2.5;
		}

		$buffer = $port;

		$server->send($buffer);
	}
}

###############################################################################
