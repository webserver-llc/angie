#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for request body to HTTP/2 backend on next upstream.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        client_body_buffer_size 8k;

        location / {
            proxy_next_upstream http_404;
            proxy_pass http://u;
            proxy_http_version 2;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        http2 on;

        location / {
            return 404;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        http2 on;

        location / {
            proxy_pass http://127.0.0.1:8080/discard;
        }

        location /discard {
            return 200;
        }
    }
}

EOF

$t->try_run('no proxy_http_version 2')->plan(1);

###############################################################################

# request body in next upstream

TODO: {
local $TODO = 'not yet' unless $t->read_file('nginx.conf') =~ /sendfile on/;

# bug: request body last_buf isn't cleared
# resulting in END_STREAM set prematurely on 1st DATA frame on next upstream

like(http_get_body('/', '0123456789' x 1024), qr/200 OK/, 'body');

}

###############################################################################

sub http_get_body {
	my ($uri, $body) = @_;
	return http(
		"GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Transfer-Encoding: chunked" . CRLF . CRLF
		. sprintf("%x", length $body) . CRLF
		. $body . CRLF
		. "0" . CRLF . CRLF
	);
}

###############################################################################
