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
use Test::Utils qw/get_json hash_like/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
		->has(qw/http proxy rewrite http_api upstream_zone/)
		->plan(12);

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
        server 127.0.0.1:%%PORT_8081%% max_fails=1 fail_timeout=2s slow_start=5s weight=2;
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

hash_like(many(30), {$p1 => 20, $p2 => 10}, 0, 'weighted');

# fail the peer
$t->write_file('dead', '');

hash_like(many(30), {}, 0, 'dead');

# ensure it is now unhealthy
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "unavailable", "backend 1 is now unavailable");

$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "unavailable", "backend 2 is now unavailable");

# revive the peer
unlink "$d/dead";

select undef, undef, undef, 3;

# to make sure the upstream is definitely revived,
# we need to get OK response from each upstream server
my $ok_responses = {$p1 => 0, $p2 => 0};
for (1..3) {
	my ($port) = http_get('/foo') =~ /^\b(\d{4})\b$/m;
	next unless defined $port;

	last if $ok_responses->{$p1} > 0 && $ok_responses->{$p2} > 0;

	$ok_responses->{$port} ++;
}

ok($ok_responses->{$p1} && $ok_responses->{$p2}, 'both backends revived')
	or diag(explain($ok_responses));

# expect peer to be in 'recovery' state due to slow start
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "recovering", "backend 1 is recovering");

# backend without slow start must be up
$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p2");
is($r->{state}, "up", "backend 2 is up");

hash_like(many(30), {$p1 => 0, $p2 => 30}, 10, 'p2 only');

# let the slow start to complete
select undef, undef, undef, 5;

$r = get_json("/api/status/http/upstreams/u1/peers/127.0.0.1:$p1");
is($r->{state}, "up", "backend 1 is up again");

hash_like(many(30), {$p1 => 20, $p2 => 10}, 0, 'weighted again');

###############################################################################

sub many {
	my ($count) = @_;

	my %ports;
	for (1 .. $count) {
		my $res = http_get('/foo');
		if ($res && $res =~ /(\d{4})$/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	return \%ports;
}

