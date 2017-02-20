#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Nginx, Inc.

# Tests for large_client_header_buffers directive.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    connection_pool_size 64;
    client_header_buffer_size 64;

    server {
        listen       127.0.0.1:8080;
        server_name  five;

        large_client_header_buffers 5 128;

        return 204;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  ten;

        large_client_header_buffers 10 128;

        return 204;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  one;

        large_client_header_buffers 1 128;

        return 204;
    }
}

EOF

$t->run();

###############################################################################

TODO: {
todo_skip 'overflow', 2 unless $ENV{TEST_NGINX_UNSAFE};

# if hc->busy is allocated before the virtual server is selected,
# and then additional buffers are allocated in a virtual server with larger
# number of buffers configured, hc->busy will be overflowed

like(http(
	"GET / HTTP/1.0" . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"Host: ten" . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF . CRLF
), qr/204|400/, 'additional buffers in virtual server');

# for pipelined requests large header buffers are saved to hc->free;
# it sized for number of buffers in the current virtual server, but
# saves previously allocated buffers, and there may be more buffers if
# allocatad before the virtual server was selected

like(http(
	"GET / HTTP/1.1" . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"X-Foo: " . ("1234567890" x 10) . CRLF .
	"Host: one" . CRLF . CRLF .
	"GET / HTTP/1.1" . CRLF .
	"Host: one" . CRLF .
	"Connection: close" . CRLF . CRLF
), qr/204/, 'pipelined with too many buffers');

}

###############################################################################
