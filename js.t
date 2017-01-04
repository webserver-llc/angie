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
    js_set $test_var     test_var;
    js_set $test_log     test_log;

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

        location /req_var {
            return 200 $test_var;
        }

        location /req_log {
            return 200 $test_log;
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

        location /res_ihdr {
            js_content ihdr;
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
        var s = '', h;
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
        var s = '', a;
        for (a in req.args) {
            if (a.substr(0, 3) == 'foo') {
                s += req.args[a];
            }
        }
        return s;
    }

    function test_var(req, res) {
        return 'variable=' + req.variables.remote_addr;
    }

    function test_log(req, res) {
        req.log("SEE-THIS");
    }

    function status(req, res) {
        res.status = 204;
        if (res.status != 204)
            res.status = 404;
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
        if (res.contentLength != 5)
            res.contentLength = 6;
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

        if (req.args.bar) {
            res.headers['Bar'] = res.headers['Foo'];
        }

        if (req.args.bar == 'empty') {
            res.headers['Bar'] = res.headers['Baz'];
        }

        res.sendHeader();
        res.finish();
    }

    function ihdr(req, res) {
        res.status = 200;
        res.headers['a'] = req.args.a;
        res.headers['b'] = req.args.b;

        var s = '', h;
        for (h in res.headers) {
            s += res.headers[h];
        }

        res.sendHeader();
        res.send(s);
        res.finish();
    }
EOF

$t->try_run('no njs available')->plan(20);

###############################################################################

like(http_get('/req_method'), qr/method=GET/, 'req.method');
like(http_get('/req_version'), qr/version=1.0/, 'req.httpVersion');
like(http_get('/req_addr'), qr/addr=127.0.0.1/, 'req.remoteAddress');
like(http_get('/req_uri'), qr/uri=\/req_uri/, 'req.uri');
like(http_get_hdr('/req_hdr'), qr/hdr=12345/, 'req.headers');
like(http_get_ihdr('/req_ihdr'), qr/12345barz/, 'req.headers iteration');
like(http_get('/req_arg?foO=12345'), qr/arg=12345/, 'req.args');
like(http_get('/req_iarg?foo=12345&foo2=bar&nn=22&foo-3=z'), qr/12345barz/,
	'req.args iteration');
like(http_get('/req_var'), qr/variable=127.0.0.1/, 'req.variables');
like(http_get('/req_log'), qr/200 OK/, 'req.log');

like(http_get('/res_status'), qr/204 No Content/, 'res.status');
like(http_get('/res_ctype'), qr/Content-Type: application\/foo/,
	'res.contentType');
like(http_get('/res_clen'), qr/Content-Length: 5/, 'res.contentLength');
like(http_get('/res_send?foo=12345&n=11&foo-2=bar&ndd=&foo-3=z'),
	qr/n=foo, v=12 n=foo-2, v=ba n=foo-3, v=z/, 'res.send');
like(http_get('/res_hdr?foo=12345'), qr/Foo: 12345/, 'res.headers');
like(http_get('/res_hdr?foo=123&bar=copy'), qr/Bar: 123/, 'res.headers get');
like(http_get('/res_hdr?bar=empty'), qr/Bar: \x0d/, 'res.headers empty');
like(http_get('/res_ihdr?a=12&b=34'), qr/^1234$/m, 'res.headers iteration');

TODO: {
local $TODO = 'zero size buf in writer';

like(http_get('/res_ihdr'), qr/\x0d\x0a?\x0d\x0a?$/m, 'res.send zero');

$t->todo_alerts();

}

$t->stop();

ok(index($t->read_file('error.log'), 'SEE-THIS') > 0, 'log js');

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
