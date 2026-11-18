#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for reusing a cached HTTP/3 upstream connection after the proxied
# server has sent a GOAWAY frame.  Such a connection must not be reused; the
# request must be sent over a new upstream connection instead of failing with
# 502.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite http_v3/)
	->has("upstream_keepalive")->has_daemon('openssl')->plan(5);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%%;

        keepalive 1;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_http_version        3;
            proxy_next_upstream       off;

            proxy_pass https://u;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        keepalive_requests 1;

        location / {
            return 200 "primary\n";
        }
    }
}

EOF

$t->run();

###############################################################################

my $res;

# the first request primes a cached upstream connection; after the single
# request that "keepalive_requests 1" allows, the server sends a GOAWAY frame

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 1 is 200');

# the following requests must not reuse the cached connection that received
# GOAWAY and must be sent over a new upstream connection instead of failing
# with 502

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 2 is 200');

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 3 is 200');

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 4 is 200');

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 5 is 200');

###############################################################################
