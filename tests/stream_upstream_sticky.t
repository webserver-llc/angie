#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for stream upstream sticky module

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

my $t = Test::Nginx->new()
	->has(qw/stream stream_ssl http ssl stream_upstream_zone/)->plan(13)
	->has_daemon('openssl')
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format  status  "$status $upstream_addr $upstream_sticky_status";

    map $ssl_preread_server_name $route {
        b1.example.com           a;
        b2.example.com           b;
        b3.example.com           unknown;
        default                  "";
    }

    upstream u_route {
        server 127.0.0.1:8081 sid=a;
        server 127.0.0.1:8082 sid=b;
        zone z 1m;

        sticky route $route;
    }

    server {
        listen      127.0.0.1:8090;
        ssl_preread on;
        proxy_pass  u_route;

        access_log  %%TESTDIR%%/stream-access.log status;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen 127.0.0.1:8081 ssl;
        server_name b1.example.com;
        location / {
            return 200 "B1";
        }
    }

    server {
        listen 127.0.0.1:8082 ssl;
        server_name b2.example.com;
        location / {
            return 200 "B2";
        }
    }

    server {
        listen 127.0.0.1:8080;

        proxy_ssl_session_reuse off;
        proxy_ssl_server_name on;

        location /api/ {
            api /;
        }

        location /any {
            proxy_ssl_name "something";
            proxy_pass https://127.0.0.1:8090;
        }

        location /b1_route {
            proxy_ssl_name b1.example.com;
            proxy_pass https://127.0.0.1:8090;
        }

        location /b2_route {
            proxy_ssl_name b2.example.com;
            proxy_pass https://127.0.0.1:8090;
        }

        location /b3_route {
            proxy_ssl_name b3.example.com;
            proxy_pass https://127.0.0.1:8090;
        }
    }
}

EOF

$t->prepare_ssl();

$t->run();


###############################################################################

my ($port1, $port2) = (port(8081), port(8082));

# expect RR for requests without known route
like(http_get("/any"),"/B1/", "B1 initial RR");
like(http_get("/any"),"/B2/", "B2 RR switch 1");
like(http_get("/any"),"/B1/", "B1 RR switch 2");
like(http_get("/any"),"/B2/", "B2 RR switch 3");

# expect sticky for requests with known route
like(http_get("/b1_route"),"/B1/", "initial B1 request");
like(http_get("/b1_route"),"/B1/", "expected sticky B1 request");
like(http_get("/b2_route"),"/B2/", "initial B2 request");
like(http_get("/b2_route"),"/B2/", "expected sticky B2");

like(http_get("/b3_route"),"/B1/", "fallback to RR1");
like(http_get("/b3_route"),"/B2/", "fallback to RR2");

###############################################################################
my $j;

# check that API returns SID values for peers correctly

$j = get_json("/api/status/stream/upstreams/u_route/peers/127.0.0.1:$port1");
is($j->{'sid'}, "a", "b1 has proper sid");

$j = get_json("/api/status/stream/upstreams/u_route/peers/127.0.0.1:$port2");
is($j->{'sid'}, "b", "b2 has proper sid");

###############################################################################

$t->stop();

my $log = $t->read_file('stream-access.log');

# first 4 connections are NEW (no route info, variable empty)
# next 4 connections are HIT (route given, correct backends reached)
# last 2 connections are MISS (route given, but does not match known)
my $expected = <<EOF;
200 127.0.0.1:$port1 NEW
200 127.0.0.1:$port2 NEW
200 127.0.0.1:$port1 NEW
200 127.0.0.1:$port2 NEW
200 127.0.0.1:$port1 HIT
200 127.0.0.1:$port1 HIT
200 127.0.0.1:$port2 HIT
200 127.0.0.1:$port2 HIT
200 127.0.0.1:$port1 MISS
200 127.0.0.1:$port2 MISS
EOF

is($log, $expected, "sticky status variable good");
