#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Maxim Dounin

# Tests for http proxy cache, proxy_no_cache.

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

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/)->plan(16)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache keys_zone=one:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;

            proxy_cache one;
            proxy_cache_key $uri;
            proxy_cache_valid any 1y;
            proxy_no_cache $arg_nocache;

            proxy_intercept_errors on;
            error_page 404 = @fallback;
        }

        location /t3 {
            proxy_pass http://127.0.0.1:8081;

            proxy_cache one;
            proxy_cache_key $uri;
            proxy_cache_valid any 1y;
            proxy_no_cache $arg_nocache;
        }

        location /t4 {
            proxy_pass http://127.0.0.1:8081;

            proxy_cache one;
            proxy_cache_key $uri;
            proxy_cache_valid any 1s;
            proxy_no_cache $upstream_http_x_no_cache;

            proxy_cache_revalidate on;
        }

        location @fallback {
            return 403;
        }

        add_header X-Cache-Status $upstream_cache_status always;
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
        }

        location /t3 {
            set $nocache "";
            if ($arg_expires) {
                set $nocache "no-cache";
            }
            add_header Cache-Control $nocache;
            add_header Transfer-Encoding invalid;
        }

        location /t4 {
            set $nocache "";
            if ($arg_expires) {
                set $nocache "no-cache";
            }
            add_header Cache-Control $nocache;
            add_header X-No-Cache $arg_nocache;
        }
    }
}

EOF

$t->write_file('t', 'SEE-THIS');
$t->write_file('t3', 'SEE-THIS');
$t->write_file('t4', 'SEE-THIS');

$t->run();

###############################################################################

like(http_get('/t?nocache=1'), qr/MISS.*SEE-THIS/s, 'request');
like(http_get('/t'), qr/MISS.*SEE-THIS/s, 'request not cached');
like(http_get('/t'), qr/HIT.*SEE-THIS/s, 'request cached');

# proxy_no_cache with intercepted errors,
# ngx_http_upstream_intercept_errors()

like(http_get('/t2?nocache=1'), qr/403 Forbidden/, 'intercepted error');
like(http_get('/t2'), qr/403 Forbidden.*MISS/s, 'intercepted error not cached');
like(http_get('/t2'), qr/403 Forbidden.*HIT/s, 'intercepted error cached');

# proxy_no_cache with internal 502/504 errors,
# ngx_http_upstream_finalize_request()

like(http_get('/t3?nocache=1'), qr/502 Bad/, 'internal 502 error');
like(http_get('/t3?expires=1'), qr/502 Bad.*MISS/s,
	'internal 502 error expires');
like(http_get('/t3'), qr/502 Bad.*MISS/s, 'internal 502 error not cached');
like(http_get('/t3'), qr/502 Bad.*HIT/s, 'internal 502 error cached');

# proxy_no_cache with revalidate and 304,
# ngx_http_upstream_test_next()

like(http_get('/t4'), qr/MISS.*SEE-THIS/s, 'revalidate');
like(http_get('/t4'), qr/HIT.*SEE-THIS/s, 'revalidate cached');
select undef, undef, undef, 2.5;
like(http_get('/t4?nocache=1'), qr/REVALIDATED.*SEE-THIS/s,
	'revalidate nocache');
like(http_get('/t4?expires=1'), qr/REVALIDATED.*SEE-THIS/s,
	'revalidate expires');
like(http_get('/t4'), qr/REVALIDATED.*SEE-THIS/s,
	'revalidate again');
like(http_get('/t4'), qr/HIT.*SEE-THIS/s, 'revalidate again cached');

###############################################################################
