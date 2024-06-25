#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Maxim Dounin

# Tests for http proxy cache, proxy_cache_bypass.

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

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/)->plan(12)
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
            proxy_cache_bypass $arg_bypass;
            proxy_cache_valid any 1y;

            proxy_intercept_errors on;
            error_page 404 = @fallback;
        }

        location @fallback {
            return 403;
        }

        add_header X-Cache-Status $upstream_cache_status;
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
        }

        location /t3 {
            add_header Transfer-Encoding $arg_bypass;
        }
    }
}

EOF

$t->write_file('t', 'SEE-THIS');
$t->write_file('t3', 'SEE-THIS');

$t->run();

###############################################################################

like(http_get('/t'), qr/SEE-THIS/, 'request');

$t->write_file('t', 'NOOP');

like(http_get('/t'), qr/SEE-THIS/, 'request cached');
like(http_get('/t?bypass=1'), qr/NOOP/, 'cache bypassed');

unlink $t->testdir() . '/t';

like(http_get('/t'), qr/NOOP/, 'cached after bypass');

# ticket #827, cache item "error" field was not cleared
# on cache bypass

like(http_get('/t2'), qr/403 Forbidden/, 'intercepted error');

$t->write_file('t2', 'NOOP');

like(http_get('/t2'), qr/403 Forbidden/, 'error cached');
like(http_get('/t2?bypass=1'), qr/NOOP/, 'error cache bypassed');

unlink $t->testdir() . '/t2';

like(http_get('/t2'), qr/NOOP/, 'file cached after bypass');

# make sure the error is cached after bypass

like(http_get('/t2?bypass=1'), qr/403 Forbidden/, 'file cache bypassed');

$t->write_file('t2', 'NOOP');

like(http_get('/t2'), qr/403 Forbidden/, 'error cached again');

# similarly, internal 502/504 is cached after bypass

like(http_get('/t3?bypass=1'), qr/502 Bad/, 'internal 502');

like(http_get('/t3'), qr/502 Bad/, 'internal 502 cached');

###############################################################################
