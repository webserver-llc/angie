#!/usr/bin/perl

# (C) Nginx, Inc.
# (C) 2024 Web Server LLC

# Tests for HTTP/3 proxying with variables

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
	->has_daemon("openssl")->plan(1);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%$arg_foo;
            proxy_http_version  3;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        location / {
            return 200 OK;
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/'), qr/200 OK/, 'response good');

