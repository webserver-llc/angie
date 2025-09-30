#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for http proxy cache with proxy_method.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(24)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=kz:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /on {
            proxy_pass            http://127.0.0.1:8081/;
            proxy_cache           kz;
            proxy_cache_valid     any 1m;
            proxy_cache_min_uses  1;

            proxy_method $arg_method;
            #proxy_cache_convert_head on; # "on" is default

            add_header X-Upstream-Method $upstream_request_method;
        }

        location /off {
            proxy_pass            http://127.0.0.1:8081/;
            proxy_cache           kz;
            proxy_cache_valid     any 1m;
            proxy_cache_min_uses  1;

            proxy_method $arg_method;
            proxy_cache_convert_head off;

            add_header X-Upstream-Method $upstream_request_method;
        }

    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;
        location / {
            add_header X-Method $request_method;
        }
    }
}

EOF

$t->write_file('t1.html', 'SEE-THIS');
$t->write_file('t2.html', 'SEE-THIS');
$t->write_file('t3.html', 'SEE-THIS');
$t->write_file('t4.html', 'SEE-THIS');

$t->write_file('t5.html', 'SEE-THIS');
$t->write_file('t6.html', 'SEE-THIS');
$t->write_file('t7.html', 'SEE-THIS');
$t->write_file('t8.html', 'SEE-THIS');


$t->run();

###############################################################################

my $res;

$res = http_get('/on/t1.html?method=GET');
like($res, qr/X-Method: GET/, 'GET->GET on');
like($res, qr/X-Upstream-Method: GET/, '$upstream_request_method is GET');
like($res, qr/SEE-THIS/, 'proxy request body ok');

$res = http_get('/on/t2.html?method=HEAD');
like($res, qr/X-Method: HEAD/, 'GET->HEAD on');
like($res, qr/X-Upstream-Method: HEAD/, '$upstream_request_method is HEAD');
unlike($res, qr/SEE-THIS/, 'proxy request no body');


$res = http_head('/on/t3.html?method=GET');
like($res, qr/X-Method: GET/, 'HEAD->GET on');
like($res, qr/X-Upstream-Method: GET/, '$upstream_request_method is GET');
unlike($res, qr/SEE-THIS/, 'proxy request no body');

$res = http_head('/on/t4.html?method=HEAD');
like($res, qr/X-Method: HEAD/, 'HEAD->HEAD on');
like($res, qr/X-Upstream-Method: HEAD/, '$upstream_request_method is HEAD');
unlike($res, qr/SEE-THIS/, 'proxy request no body');

$res = http_get('/off/t5.html?method=GET');
like($res, qr/X-Method: GET/, 'GET->GET off');
like($res, qr/X-Upstream-Method: GET/, '$upstream_request_method is GET');
like($res, qr/SEE-THIS/, 'proxy request body ok');

$res = http_get('/off/t6.html?method=HEAD');
like($res, qr/X-Method: HEAD/, 'GET->HEAD off');
like($res, qr/X-Upstream-Method: HEAD/, '$upstream_request_method is HEAD');
unlike($res, qr/SEE-THIS/, 'proxy request no body');

$res = http_head('/off/t7.html?method=GET');
like($res, qr/X-Method: GET/, 'HEAD->GET off');
like($res, qr/X-Upstream-Method: GET/, '$upstream_request_method is GET');
unlike($res, qr/SEE-THIS/, 'proxy request no body');

$res = http_head('/off/t8.html?method=HEAD');
like($res, qr/X-Method: HEAD/, 'HEAD->HEAD off');
like($res, qr/X-Upstream-Method: HEAD/, '$upstream_request_method is HEAD');
unlike($res, qr/SEE-THIS/, 'proxy request no body');

