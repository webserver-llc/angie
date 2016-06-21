#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Stream tests for upstream hash balancer module with datagrams.

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

my $t = Test::Nginx->new()->has(qw/stream stream_upstream_hash udp/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    proxy_responses      1;
    proxy_timeout        1s;

    upstream hash {
        hash $remote_addr;
        server 127.0.0.1:%%PORT_2_UDP%%;
        server 127.0.0.1:%%PORT_3_UDP%%;
    }

    upstream cons {
        hash $remote_addr consistent;
        server 127.0.0.1:%%PORT_2_UDP%%;
        server 127.0.0.1:%%PORT_3_UDP%%;
    }

    server {
        listen      127.0.0.1:%%PORT_0_UDP%% udp;
        proxy_pass  hash;
    }

    server {
        listen      127.0.0.1:%%PORT_1_UDP%% udp;
        proxy_pass  cons;
    }
}

EOF

$t->run_daemon(\&udp_daemon, port(2), $t);
$t->run_daemon(\&udp_daemon, port(3), $t);
$t->try_run('no stream udp')->plan(2);

$t->waitforfile($t->testdir . '/' . port(2));
$t->waitforfile($t->testdir . '/' . port(3));

###############################################################################

my @ports = my ($port2, $port3) = (port(2), port(3));

is(many(10, port(0)), "$port3: 10", 'hash');
like(many(10, port(1)), qr/($port2|$port3): 10/, 'hash consistent');

###############################################################################

sub many {
	my ($count, $port) = @_;
	my (%ports);

	for (1 .. $count) {
		if (dgram("127.0.0.1:$port")->io('.') =~ /(\d+)/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	my @keys = map { my $p = $_; grep { $p == $_ } keys %ports } @ports;
	return join ', ', map { $_ . ": " . $ports{$_} } @keys;
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
		$buffer = $server->sockport();
		$server->send($buffer);
	}
}

###############################################################################
