#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http njs module, working with headers.

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

my $t = Test::Nginx->new()->has(qw/http charset/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    js_set $test_foo_in   test_foo_in;
    js_set $test_ifoo_in  test_ifoo_in;

    js_include test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /njs {
            js_content test_njs;
        }

        location /content_length {
            js_content content_length;
        }

        location /content_type {
            charset windows-1251;

            default_type text/plain;
            js_content content_type;
        }

        location /content_encoding {
            js_content content_encoding;
        }

        location /headers_list {
            js_content headers_list;
        }

        location /foo_in {
            return 200 $test_foo_in;
        }

        location /ifoo_in {
            return 200 $test_ifoo_in;
        }

        location /hdr_in {
            js_content hdr_in;
        }

        location /hdr_out {
            js_content hdr_out;
        }

        location /ihdr_out {
            js_content ihdr_out;
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function content_length(r) {
        r.headersOut['Content-Length'] = '';
        r.headersOut['Content-Length'] = 3;
        delete r.headersOut['Content-Length'];
        r.headersOut['Content-Length'] = 3;
        r.sendHeader();
        r.send('XXX');
        r.finish();
    }

    function content_type(r) {
        r.headersOut['Content-Type'] = 'text/xml';
        r.headersOut['Content-Type'] = '';
        r.headersOut['Content-Type'] = 'text/xml; charset=';
        delete r.headersOut['Content-Type'];
        r.headersOut['Content-Type'] = 'text/xml; charset=utf-8';
        r.headersOut['Content-Type'] = 'text/xml; charset="utf-8"';
        r.return(200);
    }

    function content_encoding(r) {
        r.headersOut['Content-Encoding'] = '';
        r.headersOut['Content-Encoding'] = 'test';
        delete r.headersOut['Content-Encoding'];
        r.headersOut['Content-Encoding'] = 'gzip';
        r.return(200);
    }

    function headers_list(r) {
        for (var h in {a:1, b:2, c:3}) {
            r.headersOut[h] = h;
        }

        delete r.headersOut.b;
        r.headersOut.d = 'd';

        var out = "";
        for (var h in r.headersOut) {
            out += h + ":";
        }

        r.return(200, out);
    }

    function hdr_in(r) {
        var s = '', h;
        for (h in r.headersIn) {
            s += `\${h.toLowerCase()}: \${r.headersIn[h]}\n`;
        }

        r.return(200, s);
    }

    function test_foo_in(r) {
        return 'hdr=' + r.headersIn.foo;
    }

    function test_ifoo_in(r) {
        var s = '', h;
        for (h in r.headersIn) {
            if (h.substr(0, 3) == 'foo') {
                s += r.headersIn[h];
            }
        }
        return s;
    }

    function hdr_out(r) {
        r.status = 200;
        r.headersOut['Foo'] = r.args.fOO;

        if (r.args.bar) {
            r.headersOut['Bar'] =
                r.headersOut[(r.args.bar == 'empty' ? 'Baz' :'Foo')]
        }

        r.sendHeader();
        r.finish();
    }

    function ihdr_out(r) {
        r.status = 200;
        r.headersOut['a'] = r.args.a;
        r.headersOut['b'] = r.args.b;

        var s = '', h;
        for (h in r.headersOut) {
            s += r.headersOut[h];
        }

        r.sendHeader();
        r.send(s);
        r.finish();
    }


EOF

$t->try_run('no njs')->plan(16);

###############################################################################

like(http_get('/content_length'), qr/Content-Length: 3/,
	'set Content-Length');
like(http_get('/content_type'), qr/Content-Type: text\/xml; charset="utf-8"\r/,
	'set Content-Type');
unlike(http_get('/content_type'), qr/Content-Type: text\/plain/,
	'set Content-Type 2');
like(http_get('/content_encoding'), qr/Content-Encoding: gzip/,
	'set Content-Encoding');
like(http_get('/headers_list'), qr/a:c:d/, 'headers list');

like(http_get('/ihdr_out?a=12&b=34'), qr/^1234$/m, 'r.headersOut iteration');
like(http_get('/ihdr_out'), qr/\x0d\x0a?\x0d\x0a?$/m, 'r.send zero');
like(http_get('/hdr_out?foo=12345'), qr/Foo: 12345/, 'r.headersOut');
like(http_get('/hdr_out?foo=123&bar=copy'), qr/Bar: 123/, 'r.headersOut get');
unlike(http_get('/hdr_out?bar=empty'), qr/Bar:/, 'r.headersOut empty');
unlike(http_get('/hdr_out?foo='), qr/Foo:/, 'r.headersOut no value');
unlike(http_get('/hdr_out?foo'), qr/Foo:/, 'r.headersOut no value 2');

like(http(
	'GET /hdr_in HTTP/1.0' . CRLF
	. 'Cookie: foo' . CRLF
	. 'Host: localhost' . CRLF . CRLF
), qr/cookie: foo/, 'r.headersIn cookie');

like(http(
	'GET /hdr_in HTTP/1.0' . CRLF
	. 'X-Forwarded-For: foo' . CRLF
	. 'Host: localhost' . CRLF . CRLF
), qr/x-forwarded-for: foo/, 'r.headersIn xff');


TODO: {
local $TODO = 'not yet'
               unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.3.6';

like(http(
	'GET /hdr_in HTTP/1.0' . CRLF
	. 'Cookie: foo1' . CRLF
	. 'Cookie: foo2' . CRLF
	. 'Host: localhost' . CRLF . CRLF
), qr/cookie: foo1; foo2/, 'r.headersIn cookie2');

like(http(
	'GET /hdr_in HTTP/1.0' . CRLF
	. 'X-Forwarded-For: foo1' . CRLF
	. 'X-Forwarded-For: foo2' . CRLF
	. 'Host: localhost' . CRLF . CRLF
), qr/x-forwarded-for: foo1, foo2/, 'r.headersIn xff2');

}

###############################################################################
