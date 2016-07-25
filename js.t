#!/usr/bin/perl

# (C) Roman Arutyunyan

# Tests for http JavaScript module.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    js_set $test_method  test_method;
    js_set $test_version test_version;
    js_set $test_addr    test_addr;
    js_set $test_uri     test_uri;
    js_set $test_hdr     test_hdr;
    js_set $test_ihdr    test_ihdr;
    js_set $test_arg     test_arg;
    js_set $test_iarg    test_iarg;

    js_include test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /req_method {
            return 200 $test_method;
        }

        location /req_version {
            return 200 $test_version;
        }

        location /req_addr {
            return 200 $test_addr;
        }

        location /req_uri {
            return 200 $test_uri;
        }

        location /req_hdr {
            return 200 $test_hdr;
        }

        location /req_ihdr {
            return 200 $test_ihdr;
        }

        location /req_arg {
            return 200 $test_arg;
        }

        location /req_iarg {
            return 200 $test_iarg;
        }

        location /res_status {
            js_content status;
        }

        location /res_ctype {
            js_content ctype;
        }

        location /res_clen {
            js_content clen;
        }

        location /res_send {
            js_content send;
        }

        location /res_hdr {
            js_content hdr;
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_method(req, res) {
        return 'method=' + req.method;
    }

    function test_version(req, res) {
        return 'version=' + req.httpVersion;
    }

    function test_addr(req, res) {
        return 'addr=' + req.remoteAddress;
    }

    function test_uri(req, res) {
        return 'uri=' + req.uri;
    }

    function test_hdr(req, res) {
        return 'hdr=' + req.headers.foo;
    }

    function test_ihdr(req, res) {
        var s;
        s = '';
        for (h in req.headers) {
            if (h.substr(0, 3) == 'foo') {
                s += req.headers[h];
            }
        }
        return s;
    }

    function test_arg(req, res) {
        return 'arg=' + req.args.foo;
    }

    function test_iarg(req, res) {
        var s;
        s = '';
        for (a in req.args) {
            if (a.substr(0, 3) == 'foo') {
                s += req.args[a];
            }
        }
        return s;
    }

    function status(req, res) {
        res.status = 204;
        res.sendHeader();
        res.finish();
    }

    function ctype(req, res) {
        res.status = 200;
        res.contentType = 'application/foo';
        res.sendHeader();
        res.finish();
    }

    function clen(req, res) {
        res.status = 200;
        res.contentLength = 5;
        res.sendHeader();
        res.send('foo12');
        res.finish();
    }

    function send(req, res) {
        var a, s;
        res.status = 200;
        res.sendHeader();
        for (a in req.args) {
            if (a.substr(0, 3) == 'foo') {
                s = req.args[a];
                res.send('n=' + a + ', v=' + s.substr(0, 2) + ' ');
            }
        }
        res.finish();
    }

    function hdr(req, res) {
        res.status = 200;
        res.headers['Foo'] = req.args.fOO;
        res.sendHeader();
        res.finish();
    }
EOF

$t->try_run('no njs available')->plan(13);

###############################################################################

like(http_get('/req_method'), qr/method=GET/, 'r.method');
like(http_get('/req_version'), qr/version=1.0/, 'r.httpVersion');
like(http_get('/req_addr'), qr/addr=127.0.0.1/, 'r.remoteAddress');
like(http_get('/req_uri'), qr/uri=\/req_uri/, 'r.uri');
like(http_get_hdr('/req_hdr'), qr/hdr=12345/, 'r.headers');
like(http_get_ihdr('/req_ihdr'), qr/12345barz/, 'r.headers iteration');
like(http_get('/req_arg?foO=12345'), qr/arg=12345/, 'r.args');
like(http_get('/req_iarg?foo=12345&foo2=bar&nn=22&foo-3=z'), qr/12345barz/,
	'r.args iteration');

like(http_get('/res_status'), qr/204 No Content/, 'r.response.status');
like(http_get('/res_ctype'), qr/Content-Type: application\/foo/,
	'r.response.contentType');
like(http_get('/res_clen'), qr/Content-Length: 5/, 'r.response.contentLength');
like(http_get('/res_send?foo=12345&n=11&foo-2=bar&ndd=&foo-3=z'),
	qr/n=foo, v=12 n=foo-2, v=ba n=foo-3, v=z/, 'r.response.send');
like(http_get('/res_hdr?foo=12345'), qr/Foo: 12345/, 'r.response.headers');

###############################################################################

sub http_get_hdr {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
GET $url HTTP/1.0
FoO: 12345

EOF
}

sub http_get_ihdr {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
GET $url HTTP/1.0
foo: 12345
Host: localhost
foo2: bar
X-xxx: more
foo-3: z

EOF
}

###############################################################################
