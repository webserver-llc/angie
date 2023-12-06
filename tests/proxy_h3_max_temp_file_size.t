#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) 2023 Web Server LLC

# Tests for http proxy module, proxy_max_temp_file_size directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy http_v3/)
	->has_daemon("openssl")->plan(4);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 sndbuf=32k;
        server_name  localhost;

        proxy_buffer_size 4k;
        proxy_buffers 8 4k;

        location / {
            proxy_max_temp_file_size 4k;
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%/;
            proxy_http_version  3;
        }

        location /off/ {
            proxy_max_temp_file_size 0;
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%/;
            proxy_http_version  3;
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

$t->write_file('1', 'X' x (1024 * 1024));
$t->run();

###############################################################################

# test that the response is wholly proxied when all event pipe buffers are full

my $body = http_content(http_get('/1', sleep => 0.4));
like($body, qr/^X+$/m, 'no pipe bufs - body');
is(length($body), 1024 * 1024, 'no pipe bufs - body length');

# also with disabled proxy temp file

$body = http_content(http_get('/off/1', sleep => 0.4));
like($body, qr/^X+$/m, 'no temp file - body');
is(length($body), 1024 * 1024, 'no temp file - body length');

###############################################################################
