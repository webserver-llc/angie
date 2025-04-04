#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for proxy cache zone persistence

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/);

# see https://trac.nginx.org/nginx/ticket/1831
plan(skip_all => "perl >= 5.32 required")
	if ($t->has_module('perl') && $] < 5.032000);

$t->plan(18);

# mmap/munmap may fail due to ASLR and test does some retries
$t->todo_alerts();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format fmt '$remote_addr $request $status bytes_sent=$body_bytes_sent'
                   'ua="$upstream_addr" uc="$upstream_cache_status"';


    proxy_cache_path cache keys_zone=cz:256m:file=%%TESTDIR%%/cache.zone;

    upstream u {
        zone uz 1m;
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log access.log fmt;

        proxy_cache cz;
        proxy_cache_valid 200 1d;

        location /api/ {
            api /;
        }

        location / {
            add_header X-STATUS $upstream_cache_status;
            proxy_pass http://u/;
        }
    }

    server {
        listen 127.0.0.1:8081;

        error_log  backend_error.log;
        access_log backend_access.log fmt;

        location / {
            return 200 "backend response 0123456789 for uri=$uri\n";
        }
    }
}

EOF

my $d = $t->testdir();

# start with no state and empty cache

$t->run();

# fill the cache with some requests:

like(http_get("/a"), qr/200/, "a response");
like(http_get("/b"), qr/200/, "b response");
like(http_get("/c"), qr/200/, "c response");
like(http_get("/d"), qr/200/, "d response");

like(http_get("/a"), qr/X-STATUS: HIT/, "a cached");
like(http_get("/b"), qr/X-STATUS: HIT/, "b cached");
like(http_get("/c"), qr/X-STATUS: HIT/, "c cached");
like(http_get("/d"), qr/X-STATUS: HIT/, "d cached");

$t->stop();

# ensure we have state files created

$t->waitforfile("$d/cache.zone");

my $czone_found = 1 if -e "$d/cache.zone";
is($czone_found, 1, "cache.zone state file created");

# now restart using state files and no backend - we expect to have all in cache

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format fmt '$remote_addr $request $status bytes_sent=$body_bytes_sent'
                   'ua="$upstream_addr" uc="$upstream_cache_status"';


    proxy_cache_path cache keys_zone=cz:256m:file=%%TESTDIR%%/cache.zone;

    upstream u {
        zone uz 1m;
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log access.log fmt;

        proxy_cache cz;
        proxy_cache_valid 200 1d;

        location /api/ {
            api /;
        }

        location / {
            add_header X-STATUS $upstream_cache_status;
            proxy_pass http://u/;
        }
    }
}

EOF

$t->retry_run(20);

# the cache zone content is loaded from state file - check this


# access existing entries
like(http_get("/a"), qr/X-STATUS: HIT/, "existing a cache");
like(http_get("/b"), qr/X-STATUS: HIT/, "existing b cache");
like(http_get("/c"), qr/X-STATUS: HIT/, "existing c cache");
like(http_get("/d"), qr/X-STATUS: HIT/, "existing d cache");

$t->stop();

# restore backend

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format fmt '$remote_addr $request $status bytes_sent=$body_bytes_sent'
                   'ua="$upstream_addr" uc="$upstream_cache_status"';


    proxy_cache_path cache keys_zone=cz:256m:file=%%TESTDIR%%/cache.zone;

    upstream u {
        zone uz 1m;
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log access.log fmt;

        proxy_cache cz;
        proxy_cache_valid 200 1d;

        location /api/ {
            api /;
        }

        location / {
            add_header X-STATUS $upstream_cache_status;
            proxy_pass http://u/;
        }
    }

    server {
        listen 127.0.0.1:8081;

        error_log  backend_error.log;
        access_log backend_access.log fmt;

        location / {
            return 200 "backend response 0123456789 for uri=$uri\n";
        }
    }
}

EOF

$t->retry_run(20);

# we still can add entries
#
like(http_get("/bbb"), qr/200/, "new response");
like(http_get("/bbb"), qr/X-STATUS: HIT/, "new response cached");

$t->reload('/api/status/angie/generation');

like(http_get("/a"), qr/X-STATUS: HIT/, "existing a cache");

like(http_get("/ffff"), qr/200/, "f response");
like(http_get("/ffff"), qr/X-STATUS: HIT/, "f cached");

###############################################################################
