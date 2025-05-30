#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream statistics.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply superhashof/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api proxy upstream_zone upstream_hash/)
	->plan(6)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        zone z 1m;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        server 127.0.0.1:8083 weight=32 down backup max_fails=5 max_conns=7;
    }

    upstream uk {
        zone zk 1m;
        hash $remote_addr;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        keepalive 16;
    }

    upstream ukc {
        zone zk 1m;
        hash $remote_addr consistent;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        keepalive 16;
    }

    upstream s {
        zone zk 1m;
        server 127.0.0.1:8081;
    }

    upstream f {
        zone zk 1m;

        server 127.0.0.1:8081 max_fails=2 fail_timeout=1s;
        server 127.0.0.1:8082;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://u;
        }

        location /k {
            proxy_pass http://uk;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        location /kc {
            proxy_pass http://ukc;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        location /s {
            proxy_pass http://s/;
        }

        location /f {
            proxy_pass http://f/;
            proxy_next_upstream http_429;
        }

        location /status/ {
            api /status/http/;
        }
    }

    # backends
    server {
        error_log backend1.log debug;
        listen 127.0.0.1:8081;
        location / { return 200 "B1"; }
        location /missing { return 404; }
        location /bad1 { return 42 HOHOHO; }
        location /bad2 { return 666; }
        location /b1fail { return 429; }
    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.1:8082;
        location / { return 200 "B2"; }
        location /missing { return 404; }
        location /bad1 { return 42; }
        location /bad2 { return 666; }
        location /b1fail { return 200 "B2"; }
    }
    server {
        error_log backend3.log debug;
        listen 127.0.0.1:8083;
        location / { return 200 "B3"; }
        location /missing { return 404; }
        location /bad1 { return 42; }
        location /bad2 { return 666; }
        location /b1fail { return 200 "B2"; }
    }
}

EOF

$t->run();

###############################################################################

my ($port1, $port2, $port3) = (port(8081), port(8082), port(8083));

subtest 'response counters' => sub {
	# give 1 request for each backend
	http_get('/') for 1..2;

	my $j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/responses/");
	cmp_deeply($j, {200 => 1}, 'b1 initial response count');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port2/responses/");
	cmp_deeply($j, {200 => 1}, 'b2 initial response count');

	# issue 4 requests to update counters
	http_get('/') for 1..4;

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/responses/");
	cmp_deeply($j, {200 => 3}, 'b1 new response count');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port2/responses/");
	cmp_deeply($j, {200 => 3}, 'b2 new response count');

	# issue request leading to 404 on 1st backend
	http_get('/missing');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/responses/");
	cmp_deeply($j, {200 => 3, 404 => 1}, 'good and missing requests');
};

subtest 'verify peer properties' => sub {
	my $j = get_json("/status/upstreams/u/peers/127.0.0.1:$port3/");

	my $expected_properties = {
		server    => "127.0.0.1:$port3",
		weight    => 32,
		state     => 'down',
		max_conns => 7,
		backup    => JSON::true(),
		responses => {},
		data      => {sent => 0, received => 0},
		selected  => {current => 0, total => 0},
		health    => {unavailable => 0, downtime => 0, fails => 0},
	};

	cmp_deeply($j, superhashof($expected_properties), 'peer b3 properties');
};

subtest 'verify upstream properties' => sub {
	my $j = get_json('/status/upstreams/u/');
	is(keys %{ $j->{peers} }, 3, '3 peers in upstream');
	is($j->{keepalive}, 0, 'disabled keepalive');

	SKIP: {
		skip 'requires debug', 1
			unless $t->has_module('--with-debug');

		is($j->{zone}, 'z', 'configured zone');
	}

	# keepalive upstream with hash
	$j = get_json('/status/upstreams/uk/');
	is(keys %{ $j->{peers} }, 2, '2 peers in upstream');
	is($j->{keepalive}, 0, 'zero keepalive connections');

	# establish keepalive connection to backend
	my $v = http_get('/k');

	$j = get_json('/status/upstreams/uk/');
	is($j->{keepalive}, 1, 'one keepalive connection');
};

subtest 'check bad response counters' => sub {
	http_get('/s/bad1');
	my $j = get_json("/status/upstreams/s/peers/127.0.0.1:$port1/responses");
	cmp_deeply($j, {xxx => 1}, 'response code < 100 counter incremented');

	http_get('/s/bad2');
	$j = get_json("/status/upstreams/s/peers/127.0.0.1:$port1/responses");
	cmp_deeply($j, {xxx => 2}, 'response code > 599 counter incremented');
};

subtest 'verify peer fails' => sub {
	http_get('/f/b1fail'); # this goes to b1, fails, then to b2

	my $j = get_json('/status/upstreams/f/peers');

	cmp_deeply($j->{"127.0.0.1:$port1"}{responses}, {429 => 1},
		'b1 first fail counted');
	cmp_deeply($j->{"127.0.0.1:$port2"}{responses}, {200 => 1},
		'b2 good response');

	my $b1 = $j->{"127.0.0.1:$port1"};
	is($b1->{state},              'up', 'b1 is up');
	is($b1->{health}{fails},         1, 'b1 fails incremented');
	is($b1->{health}{downstart}, undef, 'b1 not defined downstart');
	is($b1->{health}{downtime},      0, 'b1 zero downtime');
	is($b1->{health}{unavailable},   0, 'b1 zero unavailable');

	http_get('/f/b1fail'); # this goes to b2

	$j = get_json('/status/upstreams/f/peers');
	cmp_deeply($j->{"127.0.0.1:$port1"}{responses}, {429 => 1},
		'b1 no changes');
	cmp_deeply($j->{"127.0.0.1:$port2"}{responses}, {200 => 2},
		'b2 good response');

	http_get('/f/b1fail'); # this goes to b1, fails, then to b2

	$j = get_json('/status/upstreams/f/peers');

	# now b1 is supposed to be in 'unavailable' state

	cmp_deeply($j->{"127.0.0.1:$port1"}{responses}, {429 => 2},
		'b1 tried again');
	cmp_deeply($j->{"127.0.0.1:$port2"}{responses}, {200 => 3},
		'b2 good response');

	$b1 = $j->{"127.0.0.1:$port1"};
	is($b1->{state},   'unavailable', 'b1 is unavailable');
	is($b1->{health}{fails},       2, 'b1 fails incremented');
	is($b1->{health}{unavailable}, 1, 'b1 unavailable incremented');
	cmp_deeply($b1->{health}{downstart}, $TIME_RE, 'b1 defined downstart');

	# wait a bit to get downtime incremented
	# TODO: avoid delay
	select undef, undef, undef, 0.5;

	$j = get_json('/status/upstreams/f/peers');
	ok($j->{"127.0.0.1:$port1"}{health}{downtime} > 0, 'b1 nonzero downtime');

	# wait for peer to become ready to probe again
	# TODO: avoid delay
	select undef, undef, undef, 1.5;

	http_get('/f/') for 1..2;

	$j = get_json("/status/upstreams/f/peers/127.0.0.1:$port1");
	is($j->{state},              'up', 'b1 is up');
	is($j->{responses}{200},        1, 'b1 is processing data');
	is($j->{health}{fails},         2, 'b1 fails not incremented');
	is($j->{health}{unavailable},   1, 'b1 unavailable not incremented');
	is($j->{health}{downstart}, undef, 'b1 not defined downstart');

	# check that downtime stopped growing
	my $downtime = $j->{health}{downtime};

	# wait a bit
	select undef, undef, undef, 1;

	$j = get_json("/status/upstreams/f/peers/127.0.0.1:$port1/health/downtime");
	is($j, $downtime, 'b1 downtime stopped growing');
};

subtest 'counters after reload' => sub {
	my $j = get_json('/status/upstreams/uk/');
	is($j->{keepalive}, 1, 'nonzero keepalive connections');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/responses/");
	is($j->{200}, 3, 'peer requests');

	# now reload and check some stats...
	$t->reload();

	# TODO: avoid delay
	select undef, undef, undef, 0.5;

	# expect:
	#   - no keepalive connections
	#   - peer stats reset

	$j = get_json('/status/upstreams/uk/');
	is($j->{keepalive}, 0, 'zero keepalive connections after reload');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/responses/");
	is($j->{200}, undef, 'no peer requests after reload');

	# use consistent hash
	http_get('/kc');

	$j = get_json("/status/upstreams/ukc/peers/127.0.0.1:$port1/responses/");
	my $v = $j->{200} // 0;

	$j = get_json("/status/upstreams/ukc/peers/127.0.0.1:$port2/responses/");
	if (defined $j->{200}) {
		$v = $v + $j->{200};
	}

	is($v, 1, '1 request total to consistent hash upstream');
};

###############################################################################

