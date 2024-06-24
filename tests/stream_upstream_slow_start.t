#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for stream upstream slow start

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream sequential_daemon/;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
		->has(qw/proxy http_api upstream_zone stream/)
		->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    upstream u1 {
        zone z1 1m;
        server 127.0.0.1:%%PORT_8081%% max_fails=1 fail_timeout=2s slow_start=3s weight=2;
        server 127.0.0.1:%%PORT_8082%% fail_timeout=2s;
     }

    server {
        listen 127.0.0.1:%%PORT_8090%%;
        proxy_pass u1;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log error.log debug;

    server {
        listen 127.0.0.1:%%PORT_8080%%;

        location /api/ {
            api /;
        }
    }
}

EOF


$t->run_daemon(\&sequential_daemon, port(8081));
$t->run_daemon(\&sequential_daemon, port(8082));

$t->run();

my ($p1, $p2) = (port(8081), port(8082));

###############################################################################

# ensure we have peer up
my $r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "up", "backend 1 is good on start");

$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "up", "backend 2 is good on start");

is_deeply(many(30, port(8090)), {$p1 => 20, $p2 => 10}, 'weighted');

# fail the peer
$t->stop_daemons();

is_deeply(many(30, port(8090)), {}, 'down');

# ensure it is now unavailable
$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "unavailable", "backend 1 is now unavailable");

$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "unavailable", "backend 2 is now unavailable");

# revive the peer
$t->run_daemon(\&sequential_daemon, port(8081));
$t->run_daemon(\&sequential_daemon, port(8082));

select undef, undef, undef, 3;

stream('127.0.0.1:' . 8090)->io('.');
stream('127.0.0.1:' . 8090)->io('.');

# expect peer to be in 'recovery' state due to slow start
$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "recovering", "backend 1 is recovering");

# backend without slow start must be up
$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "up", "backend 2 is up");

is_deeply(many(30, port(8090)), {$p2 => 30}, 'p2 only');

# let the slow start to complete
select undef, undef, undef, 3;

$r = get_json("/api/status/stream/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "up", "backend 1 is up again");

is_deeply(many(30, port(8090)), {$p1 => 20, $p2 => 10}, 'weighted again');

###############################################################################

sub many {
	my ($count, $port) = @_;
	my (%ports);

	for (1 .. $count) {
		my $res = stream('127.0.0.1:' . $port)->io('.');
		if ($res && $res =~ /(\d{4})$/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	return \%ports;
}

