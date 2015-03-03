#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http proxy cache revalidation with conditional requests.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT :gzip /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=one:1m;

    proxy_cache_revalidate on;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass    http://127.0.0.1:8081;
            proxy_cache   one;

            proxy_cache_valid  200  1s;

            add_header X-Cache-Status $upstream_cache_status;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
        location /etag/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_hide_header Last-Modified;
        }
        location /201 {
            add_header Last-Modified "Mon, 02 Mar 2015 17:20:58 GMT";
            add_header Cache-Control "max-age=1";
            add_header X-If-Modified-Since $http_if_modified_since;
            return 201;
        }
    }
}

EOF

$t->write_file('t', 'SEE-THIS');
$t->write_file('t2', 'SEE-THIS');

$t->run()->plan(20);

###############################################################################

# request documents and make sure they are cached

like(http_get('/t'), qr/X-Cache-Status: MISS.*SEE/ms, 'request');
like(http_get('/t'), qr/X-Cache-Status: HIT.*SEE/ms, 'request cached');

like(http_get('/t2'), qr/X-Cache-Status: MISS.*SEE/ms, '2nd request');
like(http_get('/t2'), qr/X-Cache-Status: HIT.*SEE/ms, '2nd request cached');

like(http_get('/etag/t'), qr/X-Cache-Status: MISS.*SEE/ms, 'etag');
like(http_get('/etag/t'), qr/X-Cache-Status: HIT.*SEE/ms, 'etag cached');

like(http_get('/etag/t2'), qr/X-Cache-Status: MISS.*SEE/ms, 'etag2');
like(http_get('/etag/t2'), qr/X-Cache-Status: HIT.*SEE/ms, 'etag2 cached');

like(http_get('/201'), qr/X-Cache-Status: MISS/, 'other status');
like(http_get('/201'), qr/X-Cache-Status: HIT/, 'other status cached');

# wait for a while for cached responses to expire

select undef, undef, undef, 2.5;

# 1st document isn't modified, and should be revalidated on first request
# (a 304 status code will appear in backend's logs), then cached again

like(http_get('/t'), qr/X-Cache-Status: REVALIDATED.*SEE/ms, 'revalidated');
like(http_get('/t'), qr/X-Cache-Status: HIT.*SEE/ms, 'cached again');

select undef, undef, undef, 0.1;
like($t->read_file('access.log'), qr/ 304 /, 'not modified');

# 2nd document is recreated with a new content

$t->write_file('t2', 'NEW');
like(http_get('/t2'), qr/X-Cache-Status: EXPIRED.*NEW/ms, 'revalidate failed');
like(http_get('/t2'), qr/X-Cache-Status: HIT.*NEW/ms, 'new response cached');

# the same for etag:
# 1st document isn't modified
# 2nd document is recreated

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.7.7');

like(http_get('/etag/t'), qr/X-Cache-Status: REVALIDATED.*SEE/ms,
	'etag revalidated');

}

like(http_get('/etag/t'), qr/X-Cache-Status: HIT.*SEE/ms,
	'etag cached again');
like(http_get('/etag/t2'), qr/X-Cache-Status: EXPIRED.*NEW/ms,
	'etag2 revalidate failed');
like(http_get('/etag/t2'), qr/X-Cache-Status: HIT.*NEW/ms,
	'etag2 new response cached');

# check that conditional requests are only used for 200/206 responses

# d0ce06cb9be1 in 1.7.3 changed to ignore header filter's work to strip
# the Last-Modified header when storing non-200/206 in cache;
# 1573fc7875fa in 1.7.9 effectively turned it back.

unlike(http_get('/201'), qr/X-If-Modified/, 'other status no revalidation');

###############################################################################
