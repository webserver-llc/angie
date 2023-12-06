#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) 2023 Web Server LLC

# Tests for http proxy cache with proxy_cache_convert_head directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy cache http_v3/)
	->has_daemon("openssl")->plan(8);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_cache   NAME;

        proxy_cache_key $request_uri;

        proxy_cache_valid   200 302  2s;

        add_header X-Cache-Status $upstream_cache_status;

        location / {
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%/t.html;
            proxy_http_version  3;
            proxy_cache_convert_head   off;

            location /inner {
                proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%/t.html;
                proxy_http_version  3;
                proxy_cache_convert_head on;
            }
        }

        location /on {
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%/t.html;
            proxy_http_version  3;
            proxy_cache_convert_head on;
        }
    }
    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        location / {
            add_header X-Method $request_method;
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/'), qr/x-method: GET/, 'get');
like(http_head('/?2'), qr/x-method: HEAD/, 'head');
like(http_head('/?2'), qr/HIT/, 'head cached');
unlike(http_get('/?2'), qr/SEE-THIS/, 'get after head');

like(http_get('/on'), qr/x-method: GET/, 'on - get');
like(http_head('/on?2'), qr/x-method: GET/, 'on - head');

like(http_get('/inner'), qr/x-method: GET/, 'inner - get');
like(http_head('/inner?2'), qr/x-method: GET/, 'inner - head');

###############################################################################
