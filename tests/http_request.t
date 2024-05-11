#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for basic HTTP request parsing.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF CR LF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(41)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        return 200 ok\n;
    }
}

EOF

$t->run();

###############################################################################

# some basic HTTP/0.9, HTTP/1.0, and HTTP/1.1 requests

like(http(
	"GET /" . CRLF
), qr/^ok/s, 'http/0.9 request');

like(http(
	"GET / HTTP/1.0" . CRLF .
	CRLF
), qr/ 200 /, 'http/1.0 request');

like(http(
	"GET / HTTP/1.0" . CRLF .
	"Host: foo" . CRLF .
	CRLF
), qr/ 200 /, 'http/1.0 request with host');

like(http(
	"GET / HTTP/1.1" . CRLF .
	"Host: foo" . CRLF .
	"Connection: close" . CRLF .
	CRLF
), qr/ 200 /, 'http/1.1 request');

like(http(
	"GET / HTTP/1.1" . CRLF .
	"Connection: close" . CRLF .
	CRLF
), qr/ 400 /, 'http/1.1 request rejected without host');

like(http(
	"GET http://foo/ HTTP/1.1" . CRLF .
	"Host: foo" . CRLF .
	"Connection: close" . CRLF .
	CRLF
), qr/ 200 /, 'http/1.1 request absolute form');

# ensure an empty line is ignored before the request

like(http(CRLF . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'empty line ignored');
like(http(LF . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'empty line with just LF ignored');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.25.5');

like(http(CR . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'empty line with just CR rejected');
like(http(CRLF . CRLF . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'multiple empty lines rejected');
like(http(LF . LF . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'multiple LFs rejected');
like(http(CR . CR . "GET / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'multiple CRs rejected');

}

# method

like(http("FOO / HTTP/1.0" . CRLF . CRLF), qr/ 200 /, 'method');
like(http("FOO-BAR / HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'method with dash');
like(http("FOO_BAR / HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'method with underscore');
like(http("FOO.BAR / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'method with dot rejected');
like(http("get / HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'method in lowercase rejected');

# URI

like(http("GET /foo12.bar HTTP/1.0" . CRLF . CRLF), qr/ 200 /, 'uri');
like(http("GET /control\x0d HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'uri with CR');
like(http("GET /control\x01 HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'uri with control');
like(http("GET /control\t HTTP/1.0" . CRLF . CRLF), qr/ 400 /,
	'uri with tab');

# version

like(http(
	"GET / HTTP/1.2" . CRLF .
	"Host: foo" . CRLF .
	"Connection: close" . CRLF .
	CRLF
), qr/ 200 /, 'version 1.2');

like(http(
	"GET / HTTP/1.99" . CRLF .
	"Host: foo" . CRLF .
	"Connection: close" . CRLF .
	CRLF
), qr/ 200 /, 'version 1.99');

like(http("GET / HTTP/1.000" . CRLF . CRLF), qr/ 200 /,
	'version leading zeros');
like(http("GET / HTTP/2.0" . CRLF . CRLF), qr/ 505 /,
	'version too high rejected');
like(http("GET / HTTP/1.x" . CRLF . CRLF), qr/ 400 /,
	'version non-numeric rejected');
like(http("GET / HTTP/1.100" . CRLF . CRLF), qr/ 400 /,
	'version too high minor rejected');

like(http("GET / http/1.0" . CRLF . CRLF), qr/ 400 /,
	'lowercase protocol rejected');

# spaces in request line

like(http("GET / HTTP/1.0  " . CRLF . CRLF), qr/ 200 /,
	'spaces after version');
like(http("GET /   HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'spaces after uri');
like(http("GET   / HTTP/1.0" . CRLF . CRLF), qr/ 200 /,
	'spaces before uri');

like(http("GET / HTTP/ 1.0" . CRLF . CRLF), qr/ 400 /,
	'spaces before version rejected');
like(http("GET / HTTP /1.0" . CRLF . CRLF), qr/ 400 /,
	'spaces after protocol rejected');
like(http("GET / HT TP/1.0" . CRLF . CRLF), qr/ 400 /,
	'spaces within protocol rejected');
like(http(" GET / HTTP/ 1.0" . CRLF . CRLF), qr/ 400 /,
	'spaces before method rejected');

# headers

like(http("GET / HTTP/1.0" . CRLF . "Foo: bar" . CRLF . CRLF), qr/ 200 /,
	'header');
like(http("GET / HTTP/1.0" . CRLF . "Foo : bar" . CRLF . CRLF), qr/ 400 /,
	'header with space rejected');
like(http("GET / HTTP/1.0" . CRLF . " Foo: bar" . CRLF . CRLF), qr/ 400 /,
	'header with leading space rejected');
like(http("GET / HTTP/1.0" . CRLF . "Foo\x01: bar" . CRLF . CRLF), qr/ 400 /,
	'header with control rejected');
like(http("GET / HTTP/1.0" . CRLF . "Foo\t: bar" . CRLF . CRLF), qr/ 400 /,
	'header with tab rejected');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.27.0');

like(http("GET / HTTP/1.0" . CRLF . "Foo" . CRLF . CRLF), qr/ 400 /,
	'header without colon rejected');

}

###############################################################################
