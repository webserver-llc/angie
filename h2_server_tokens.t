#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with server_tokens directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 rewrite/)->plan(9)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2;
        server_name  localhost;

        location /200 {
            return 200;
        }

        location /404 {
            return 404;
        }

        location /off {
            server_tokens off;

            location /off/200 {
                return 200;
            }

            location /off/404 {
                return 404;
            }
        }

        location /on {
            server_tokens on;

            location /on/200 {
                return 200;
            }

            location /on/404 {
                return 404;
            }
        }
    }
}

EOF

$t->run();

###############################################################################

like(header_server('/200'), qr/^nginx\/\d+\.\d+\.\d+$/,
	'http2 tokens default 200');
like(header_server('/404'), qr/^nginx\/\d+\.\d+\.\d+$/,
	'http2 tokens default 404');
like(body('/404'), qr/nginx\/\d+\.\d+\.\d+/, 'http2 tokens default 404 body');

is(header_server('/off/200'), 'nginx', 'http2 tokens off 200');
is(header_server('/off/404'), 'nginx', 'http2 tokens off 404');
like(body('/off/404'), qr/nginx(?!\/)/, 'http2 tokens off 404 body');

like(header_server('/on/200'), qr/^nginx\/\d+\.\d+\.\d+$/,
	'http2 tokens on 200');
like(header_server('/on/404'), qr/^nginx\/\d+\.\d+\.\d+$/,
	'http2 tokens on 404');
like(body('/on/404'), qr/nginx\/\d+\.\d+\.\d+/, 'http2 tokens on 404 body');

###############################################################################

sub header_server {
	my ($path) = shift;

	my $sess = new_session();
	my $sid = new_stream($sess, { path => $path });
	my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
	return $frame->{headers}->{'server'};
}

sub body {
	my ($path) = shift;

	my $sess = new_session();
	my $sid = new_stream($sess, { path => $path });
	my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

	my ($frame) = grep { $_->{type} eq "DATA" } @$frames;
	return $frame->{'data'};
}

###############################################################################
