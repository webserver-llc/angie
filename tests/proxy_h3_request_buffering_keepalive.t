#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) 2023 Web Server LLC

# Tests for unbuffered request body and proxy with keepalive.

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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_keepalive http_v3/)
	->has_daemon("openssl")->plan(1);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream backend {
        server 127.0.0.1:%%PORT_8999_UDP%%;
        keepalive 1;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_http_version 1.1;
        proxy_set_header Connection "";

        location / {
            proxy_pass https://backend;
            proxy_http_version  3;
            add_header X-Body $request_body;
            proxy_request_buffering off;
        }
    }

    server {
        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        location / { }
    }
}

EOF

$t->write_file('t1', 'SEE-THIS');
$t->run();

###############################################################################

# We emulate an early upstream server response while proxy is still
# transmitting the request body.  In this case, the request body is
# discarded by proxy, and 2nd request will be processed by upstream
# as remain request body.

http(<<EOF);
GET /t1 HTTP/1.0
Host: localhost
Content-Length: 10

EOF

like(http_get('/t1'), qr/200 OK.*SEE/ms, 'keepalive after discarded');

###############################################################################
