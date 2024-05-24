#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream statistics.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api proxy upstream_zone upstream_hash/)
	->plan(50)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        zone z 1m;
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%% weight=32 down backup max_fails=5 max_conns=7;
    }

    upstream uk {
        zone zk 1m;
        hash $remote_addr;
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        keepalive 16;
    }

    upstream ukc {
        zone zk 1m;
        hash $remote_addr consistent;
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        keepalive 16;
    }

    upstream s {
        zone zk 1m;
        server 127.0.0.1:%%PORT_8081%%;
    }

    upstream f {
        zone zk 1m;

        server 127.0.0.1:%%PORT_8081%% max_fails=2 fail_timeout=2s;
        server 127.0.0.1:%%PORT_8082%%;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
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

        location /api/ {
            api /;
        }
    }

    # backends
    server {
        error_log backend1.log debug;
        listen 127.0.0.1:%%PORT_8081%%;
        location / { return 200 "B1"; }
        location /missing { return 404; }
        location /bad1 { return 42 HOHOHO; }
        location /bad2 { return 666; }
        location /b1fail { return 429; }
    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.1:%%PORT_8082%%;
        location / { return 200 "B2"; }
        location /missing { return 404; }
        location /bad1 { return 42; }
        location /bad2 { return 666; }
        location /b1fail { return 200 "B2"; }
    }
    server {
        error_log backend3.log debug;
        listen 127.0.0.1:%%PORT_8083%%;
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

# give 1 request for each backend
http_get('/') for 1..2;

# perform some API request for coverage
try_api('/api/');
try_api('/api/status/');
try_api('/api/status/http/');
try_api('/api/status/http/upstreams');
try_api('/api/status/http/upstreams/u');
try_api('/api/status/http/upstreams/u/servers');
try_api("/api/status/http/upstreams/u/servers/127.0.0.1:$port1");

my $j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1/responses/");
is($j->{200}, 1, 'b1 initial response count');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port2/responses/");
is($j->{200}, 1, 'b2 initial response count');

# issue 4 requests to update counters
http_get('/') for 1..4;

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1/responses/");
is($j->{200}, 3, 'b1 new response count');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port2/responses/");
is($j->{200}, 3, 'b2 new response count');

# issue request leading to 404 on 1st backend
http_get('/missing');
$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1/responses/");
is($j->{200}, 3, 'good requests');
is($j->{404}, 1, 'missing requests');

# verify peer properties
$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port3/");

is($j->{server}, "127.0.0.1:$port3", 'server');

is($j->{weight},    32, 'weight');
is($j->{state}, 'down', 'state');
is($j->{max_conns},  7, 'max_conns');
is($j->{backup},     1, 'backup');

is($j->{response}{200}, undef , 'no response');

is($j->{data}{sent},     0 , 'sent');
is($j->{data}{received}, 0 , 'received');

is($j->{selected}{current}, 0 , 'current');
is($j->{selected}{total},   0 , 'selected');

is($j->{health}{unavailable}, 0 , 'unavailable');
is($j->{health}{downtime},    0 , 'downtime');
is($j->{health}{fails},       0 , 'fails');

# verify upstream properties
$j = get_json('/api/status/http/upstreams/u/');
is(ref $j->{peers} eq ref {}, 1, 'peers{} in upstream/');
is($j->{keepalive}, 0, 'disabled keepalive');

# requires debug
#is($j->{'zone'}, 'z', 'configured zone');

is(keys %{ $j->{'peers'} }, 3, '3 peers in upstream');

# keepalive upstream with hash
$j = get_json('/api/status/http/upstreams/uk/');
is(keys %{ $j->{peers} }, 2, '2 peers in upstream');
is($j->{keepalive}, 0, 'zero keepalive connections');

# establish keepalive connection to backend
my $v = http_get('/k');

$j = get_json('/api/status/http/upstreams/uk/');
is($j->{keepalive}, 1, 'one keepalive connection');

# check bad response counters
http_get('/s/bad1');
$j = get_json("/api/status/http/upstreams/s/peers/127.0.0.1:$port1/responses");
is($j->{xxx}, 1, "response code < 100 counter incremented");

http_get('/s/bad2');
$j = get_json("/api/status/http/upstreams/s/peers/127.0.0.1:$port1/responses");
is($j->{xxx}, 2, "response code > 599 counter incremented");

# verify peer fails

http_get('/f/b1fail'); # this goes to b1, fails, then to b2
$j = get_json("/api/status/http/upstreams/f/peers");
is($j->{"127.0.0.1:$port1"}{responses}{429}, 1, "b1 first fail counted");
is($j->{"127.0.0.1:$port2"}{responses}{200}, 1, "b2 good response");
is($j->{"127.0.0.1:$port1"}{health}{fails}, 1, "b1 fails incremented");

http_get('/f/b1fail'); # this goes to b2
$j = get_json("/api/status/http/upstreams/f/peers");
is($j->{"127.0.0.1:$port1"}{responses}{429}, 1, "b1 no changes");
is($j->{"127.0.0.1:$port2"}{responses}{200}, 2, "b2 good response");

http_get('/f/b1fail'); # this goes to b1, fails, then to b2
$j = get_json("/api/status/http/upstreams/f/peers");

# now b1 is supposed to be in 'failed' state

is($j->{"127.0.0.1:$port1"}{responses}{429}, 2, "b1 tried again");
is($j->{"127.0.0.1:$port2"}{responses}{200}, 3, "b2 good response");
is($j->{"127.0.0.1:$port1"}{state}, 'unavailable', "b1 is unavailable");
is($j->{"127.0.0.1:$port1"}{health}{fails}, 2, "b1 fails incremented");
is(defined $j->{"127.0.0.1:$port1"}{health}{downstart}, 1, "b1 defined downstart");

# wait a bit to get downtime incremented
# TODO: avoid delay
select undef, undef, undef, 0.5;

$j = get_json("/api/status/http/upstreams/f/peers");
is(defined $j->{"127.0.0.1:$port1"}{health}{downtime} > 0, 1, "b1 nonzero downtime");

# wait for peer to become ready to probe again
# TODO: avoid delay
select undef, undef, undef, 3;

http_get('/f/') for 1..2;

$j = get_json("/api/status/http/upstreams/f/peers");
is($j->{"127.0.0.1:$port1"}{responses}{200}, 1, "b1 is processing data");
is($j->{"127.0.0.1:$port1"}{state}, 'up', "b1 is up");

# now reload and check some stats...

$t->reload();

# TODO: avoid delay
select undef, undef, undef, 0.5;

# expect:
#   - no keepalive connections
#   - peer stats reset

$j = get_json('/api/status/http/upstreams/uk/');
is($j->{keepalive}, 0, 'zero keepalive connections after reload');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1/responses/");
is($j->{200}, undef, 'no peer requests after reload');

# use consistent hash
http_get('/kc');

$j = get_json("/api/status/http/upstreams/ukc/peers/127.0.0.1:$port1/responses/");
$v = $j->{200} // 0;

$j = get_json("/api/status/http/upstreams/ukc/peers/127.0.0.1:$port2/responses/");
if (defined $j->{200}) {
	$v = $v + $j->{200};
}

is($v, 1, '1 request total to consistent hash upstream');

###############################################################################

# used to increase coverage and try various API endpoints
# tests that response is valid JSON
sub try_api {
	my ($uri) = @_;
	my $j = get_json($uri);
	is(ref $j eq ref {}, 1, $uri . ' - valid JSON response');
}
