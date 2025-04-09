#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for UDP stream "proxy_connection_drop" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;
use Test::Nginx::Stream qw/dgram/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()
	->has(qw/http http_api stream stream_upstream_zone/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;

        location /api/ {
            api /;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    proxy_requests 4;
    proxy_responses 1;

    resolver 127.0.0.1:5757 valid=1s ipv6=off;
    resolver_timeout 10s;

    upstream u {
        zone z 1m;
        server test.example.com:%%PORT_8083_UDP%% resolve;
    }

    server {
        listen 127.0.0.1:%%PORT_8081_UDP%% udp;
        proxy_connection_drop on;
        proxy_pass u;
    }

    server {
        listen 127.0.0.1:%%PORT_8082_UDP%% udp;
        proxy_connection_drop off;
        proxy_pass u;
    }

}

EOF

my $addr_set1 = {'test.example.com' => ['127.0.0.1']};
my $addr_set2 = {'test.example.com' => ['127.0.0.2']};

# TODO: use substituted ports for parallel execution for DNS server
$t->start_resolver(5757, $addr_set1);

$t->run_daemon(\&udp_daemon, port(8083), $t);
$t->waitforfile($t->testdir . '/' . port(8083));

$t->run()->plan(5);

###############################################################################

# Connection drop on
my $s = dgram('127.0.0.1:' . port(8081));

my $real_port = $s->io('ping');

is($s->io('ping'), $real_port, 'Proxy connection 1');

$t->restart_resolver(5757, $addr_set2);

wait_peer('127.0.0.2');

isnt($s->io('ping'), $real_port, 'Connection drop on');

$t->restart_resolver(5757, $addr_set1);

wait_peer('127.0.0.1');

# Connection drop off
$s = dgram('127.0.0.1:' . port(8082));

$real_port = $s->io('ping');

is($s->io('ping'), $real_port, 'Proxy connection 2');

$t->restart_resolver(5757, $addr_set2);

wait_peer('127.0.0.2');

is($s->io('ping'), $real_port, 'Connection drop off');
is($s->io('ping'), $real_port, 'Connection drop off');

###############################################################################

sub udp_daemon {
	my ($port, $t) = @_;

	my $recv_data;
	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto => 'udp'
	)
		or die "Can't create listening socket: $!\n";

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (1) {
		$socket->recv($recv_data, 1024);
		$socket->send($socket->peerport());
	}
}

sub wait_peer {
	my ($peer) = @_;
	$peer .= ':' . port(8083);

	for (1 .. 50) {
		my $j = get_json('/api/status/stream/upstreams/u/');
		last if exists $j->{peers}{$peer};
		select undef, undef, undef, 0.5;
	}
}

###############################################################################
