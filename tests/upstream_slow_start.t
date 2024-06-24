#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for upstream slow start

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json getconn/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
		->has(qw/http proxy rewrite http_api upstream_zone/)
		->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log error.log debug;

    upstream u1 {
        zone z1 1m;
        server 127.0.0.1:%%PORT_8081%% max_fails=1 fail_timeout=2s slow_start=3s weight=2;
        server 127.0.0.1:%%PORT_8082%% fail_timeout=2s;
     }

    server {
        listen 127.0.0.1:%%PORT_8081%%;
        listen 127.0.0.1:%%PORT_8082%%;

        if (-f %%TESTDIR%%/dead) {
            return 503 dead;
        }

        location / {
            return 200 $server_port;
        }
    }

    server {
        listen 127.0.0.1:%%PORT_8080%%;

        location /api/ {
            api /;
        }

        location /foo {
            proxy_pass http://u1;
            proxy_next_upstream http_503;
        }
    }
}

EOF


my $d = $t->testdir();

$t->run();

my ($p1, $p2) = (port(8081), port(8082));

###############################################################################

# ensure we have peer up
my $r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "up", "backend 1 is good on start");

$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "up", "backend 2 is good on start");

is_deeply(many(30, port(8080)), {$p1 => 20, $p2 => 10}, 'weighted');

# fail the peer
$t->write_file('dead', '');

is_deeply(many(30, port(8080)), {}, 'dead');

# ensure it is now unhealthy
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "unavailable", "backend 1 is now unavailable");

$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "unavailable", "backend 2 is now unavailable");

# revive the peer
unlink "$d/dead";

select undef, undef, undef, 3;

http_get('/foo');
http_get('/foo');

# expect peer to be in 'recovery' state due to slow start
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "recovering", "backend 1 is recovering");

# backend without slow start must be up
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "up", "backend 2 is up");

is_deeply(many(30, port(8080)), {$p2 => 30}, 'p2 only');

# let the slow start to complete
select undef, undef, undef, 3;
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "up", "backend 1 is up again");

is_deeply(many(30, port(8080)), {$p1 => 20, $p2 => 10}, 'weighted again');

###############################################################################

sub many {
	my ($count, $port) = @_;
	my (%ports);

	for (1 .. $count) {
		my $res = http_get('/foo', socket => getconn('127.0.0.1', $port));
		if ($res && $res =~ /(\d{4})$/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	return \%ports;
}

