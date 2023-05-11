#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http njs module, fetch objects.

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

    js_import test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /njs {
            js_content test.njs;
        }

        location /headers {
            js_content test.headers;
        }

        location /request {
            js_content test.request;
        }

        location /response {
            js_content test.response;
        }

        location /fetch {
            js_content test.fetch;
        }

        location /fetch_multi_header {
            js_content test.fetch_multi_header;
        }

        location /method {
            return 200 $request_method;
        }

        location /header {
            return 200 $http_a;
        }

        location /body {
            js_content test.body;
        }
    }
}

EOF

my $p0 = port(8080);

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function header(r) {
        r.return(200, r.headersIn.a);
    }

    function body(r) {
        r.return(201, r.requestText);
    }

    async function run(r, tests) {
        var fails = [];
        for (var i = 0; i < tests.length; i++) {
            var v, t = tests[i];

            try {
                v = await t[1]();

            } catch (e) {
                v = e.message;
            }

            if (v != t[2]) {
                fails.push(`\${t[0]}: got "\${v}" expected: "\${t[2]}"\n`);
            }
        }

        r.return(fails.length ? 400 : 200, fails);
    }

    async function headers(r) {
        const tests = [
            ['empty', () => {
                var h = new Headers();
                return h.get('a');
             }, null],
            ['normal', () => {
                var h = new Headers({a: 'X', b: 'Z'});
                return `\${h.get('a')} \${h.get('B')}`;
             }, 'X Z'],
            ['trim value', () => {
                var h = new Headers({a: '  X   '});
                return h.get('a');
             }, 'X'],
            ['invalid header name', () => {
                const valid = "!#\$\%&'*+-.^_`|~0123456789";

                for (var i = 0; i < 128; i++) {
                    var c = String.fromCodePoint(i);

                    if (valid.indexOf(c) != -1 || /[a-zA-Z]+/.test(c)) {
                        continue;
                    }

                    try {
                        new Headers([[c, 'a']]);
                        throw new Error(
                                   `header with "\${c}" (\${i}) should throw`);

                    } catch (e) {
                        if (e.message != 'invalid header name') {
                            throw e;
                        }
                    }
                }

                return 'OK';

             }, 'OK'],
            ['invalid header value', () => {
                var h = new Headers({A: 'aa\x00a'});
             }, 'invalid header value'],
            ['combine', () => {
                var h = new Headers({a: 'X', A: 'Z'});
                return h.get('a');
             }, 'X, Z'],
            ['combine2', () => {
                var h = new Headers([['A', 'x'], ['a', 'z']]);
                return h.get('a');
             }, 'x, z'],
            ['combine3', () => {
                var h = new Headers();
                h.append('a', 'A');
                h.append('a', 'B');
                h.append('a', 'C');
                h.append('a', 'D');
                h.append('a', 'E');
                h.append('a', 'F');
                return h.get('a');
             }, 'A, B, C, D, E, F'],
            ['getAll', () => {
                var h = new Headers({a: 'X', A: 'Z'});
                return njs.dump(h.getAll('a'));
             }, "['X','Z']"],
            ['inherit', () => {
                var h = new Headers({a: 'X', b: 'Y'});
                var h2 = new Headers(h);
                h2.append('c', 'Z');
                return h2.has('a') && h2.has('B') && h2.has('c');
             }, true],
            ['delete', () => {
                var h = new Headers({a: 'X', b: 'Z'});
                h.delete('b');
                return h.get('a') && !h.get('b');
             }, true],
            ['forEach', () => {
                var r = [];
                var h = new Headers({a: '0', b: '1', c: '2'});
                h.delete('b');
                h.append('z', '3');
                h.append('a', '4');
                h.append('q', '5');
                h.forEach((v, k) => { r.push(`\${v}:\${k}`)})
                return r.join('|');
             }, 'a:0, 4|c:2|q:5|z:3'],
            ['set', () => {
                var h = new Headers([['A', 'x'], ['a', 'y'], ['a', 'z']]);
                h.set('a', '#');
                return h.get('a');
             }, '#'],
        ];

        run(r, tests);
    }

    async function request(r) {
        const tests = [
            ['empty', () => {
                try {
                    new Request();
                    throw new Error(`Request() should throw`);

                } catch (e) {
                    if (e.message != '1st argument is required') {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['normal', () => {
                var r = new Request("http://nginx.org",
                                    {headers: {a: 'X', b: 'Y'}});
                return `\${r.url}: \${r.method} \${r.headers.a}`;
             }, 'http://nginx.org: GET X'],
            ['url trim', () => {
                var r = new Request("\\x00\\x01\\x02\\x03\\x05\\x06\\x07\\x08"
                                    + "\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"
                                    + "\\x10\\x11\\x12\\x13\\x14\\x15\\x16"
                                    + "\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d"
                                    + "\\x1e\\x1f\\x20http://nginx.org\\x00"
                                    + "\\x01\\x02\\x03\\x05\\x06\\x07\\x08"
                                    + "\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"
                                    + "\\x10\\x11\\x12\\x13\\x14\\x15\\x16"
                                    + "\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d"
                                    + "\\x1e\\x1f\\x20");
                return r.url;
             }, 'http://nginx.org'],
            ['read only', () => {
                var r = new Request("http://nginx.org");

                const props = ['bodyUsed', 'cache', 'credentials', 'headers',
                               'method', 'mode', 'url'];
                try {
                    props.forEach(prop => {
                        r[prop] = 1;
                        throw new Error(
                                    `setting read-only \${prop} should throw`);
                    })

                } catch (e) {
                    if (!e.message.startsWith('Cannot assign to read-only p')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['cache', () => {
                const props = ['default', 'no-cache', 'no-store', 'reload',
                               'force-cache', 'only-if-cached', '#'];
                try {
                    props.forEach(cv => {
                        var r = new Request("http://nginx.org", {cache: cv});
                        if (r.cache != cv) {
                            throw new Error(`r.cache != \${cv}`);
                        }
                    })

                } catch (e) {
                    if (!e.message.startsWith('unknown cache type: #')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['credentials', () => {
                const props = ['omit', 'include', 'same-origin', '#'];
                try {
                    props.forEach(cr => {
                        var r = new Request("http://nginx.org",
                                            {credentials: cr});
                        if (r.credentials != cr) {
                            throw new Error(`r.credentials != \${cr}`);
                        }
                    })

                } catch (e) {
                    if (!e.message.startsWith('unknown credentials type: #')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['method', () => {
                const methods = ['get', 'hEad', 'Post', 'OPTIONS', 'PUT',
                                 'DELETE', 'CONNECT'];
                try {
                    methods.forEach(m => {
                        var r = new Request("http://nginx.org", {method: m});
                        if (r.method != m.toUpperCase()) {
                            throw new Error(`r.method != \${m}`);
                        }
                    })

                } catch (e) {
                    if (!e.message.startsWith('forbidden method: CONNECT')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['mode', () => {
                const props = ['same-origin', 'cors', 'no-cors', 'navigate',
                               'websocket', '#'];
                try {
                    props.forEach(m => {
                        var r = new Request("http://nginx.org", {mode: m});
                        if (r.mode != m) {
                            throw new Error(`r.mode != \${m}`);
                        }
                    })

                } catch (e) {
                    if (!e.message.startsWith('unknown mode type: #')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
            ['inherit', () => {
                var r = new Request("http://nginx.org",
                                    {headers: {a: 'X', b: 'Y'}});
                var r2 = new Request(r);
                r2.headers.append('a', 'Z')
                return `\${r2.url}: \${r2.headers.get('a')}`;
             }, 'http://nginx.org: X, Z'],
            ['inherit2', () => {
                var r = new Request("http://nginx.org",
                                    {headers: {a: 'X', b: 'Y'}});
                var r2 = new Request(r);
                r2.headers.append('a', 'Z')
                return `\${r.url}: \${r.headers.get('a')}`;
             }, 'http://nginx.org: X'],
            ['inherit3', () => {
                var h = new Headers();
                h.append('a', 'X');
                h.append('a', 'Z');
                var r = new Request("http://nginx.org", {headers: h});
                return `\${r.url}: \${r.headers.get('a')}`;
             }, 'http://nginx.org: X, Z'],
            ['content type', async () => {
                var r = new Request("http://nginx.org",
                                    {body: 'ABC', method: 'POST'});
                var body = await r.text();
                return `\${body}: \${r.headers.get('Content-Type')}`;
             }, 'ABC: text/plain;charset=UTF-8'],
            ['GET body', () => {
                try {
                    var r = new Request("http://nginx.org", {body: 'ABC'});

                } catch (e) {
                    if (!e.message.startsWith('Request body incompatible w')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
        ];

        run(r, tests);
    }

    async function response(r) {
        const tests = [
            ['empty', async () => {
                var r = new Response();
                var body = await r.text();
                return `\${r.url}: \${r.status} \${body} \${r.headers.get('a')}`;
             }, ': 200  null'],
            ['normal', async () => {
                var r = new Response("ABC", {headers: {a: 'X', b: 'Y'}});
                var body = await r.text();
                return `\${r.url}: \${r.status} \${body} \${r.headers.get('a')}`;
             }, ': 200 ABC X'],
            ['headers', async () => {
                var r = new Response(null,
                                    {headers: new Headers({a: 'X', b: 'Y'})});
                var body = await r.text();
                return `\${r.url}: \${body} \${r.headers.get('b')}`;
             }, ':  Y'],
            ['json', async () => {
                var r = new Response('{"a": {"b": 42}}');
                var json = await r.json();
                return json.a.b;
             }, 42],
            ['statusText', () => {
                const statuses = ['status text', 'aa\\u0000a'];
                try {
                    statuses.forEach(s => {
                        var r = new Response(null, {statusText: s});
                        if (r.statusText != s) {
                            throw new Error(`r.statusText != \${s}`);
                        }
                    })

                } catch (e) {
                    if (!e.message.startsWith('invalid Response statusText')) {
                        throw e;
                    }
                }

                return 'OK';

             }, 'OK'],
        ];

        run(r, tests);
    }

    async function fetch(r) {
        const tests = [
            ['method', async () => {
                var req = new Request("http://127.0.0.1:$p0/method",
                                      {method: 'PUT'});
                var r = await ngx.fetch(req);
                var body = await r.text();
                return `\${r.url}: \${r.status} \${body} \${r.headers.get('a')}`;
             }, 'http://127.0.0.1:$p0/method: 200 PUT null'],
            ['request body', async () => {
                var req = new Request("http://127.0.0.1:$p0/body",
                                      {body: 'foo'});
                var r = await ngx.fetch(req);
                var body = await r.text();
                return `\${r.url}: \${r.status} \${body}`;
             }, 'http://127.0.0.1:$p0/body: 201 foo'],
        ];

        run(r, tests);
    }

    async function fetch_multi_header(r) {
        const tests = [
            ['request multi header', async () => {
                var h = new Headers({a: 'X'});
                h.append('a', 'Z');
                var req = new Request("http://127.0.0.1:$p0/header",
                                      {headers: h});
                var r = await ngx.fetch(req);
                var body = await r.text();
                return `\${r.url}: \${r.status} \${body}`;
             }, 'http://127.0.0.1:$p0/header: 200 X, Z'],
        ];

        run(r, tests);
    }

     export default {njs: test_njs, body, headers, request, response, fetch,
                     fetch_multi_header};
EOF

$t->try_run('no njs')->plan(5);

###############################################################################

local $TODO = 'not yet' unless has_version('0.7.10');

like(http_get('/headers'), qr/200 OK/s, 'headers tests');
like(http_get('/request'), qr/200 OK/s, 'request tests');
like(http_get('/response'), qr/200 OK/s, 'response tests');
like(http_get('/fetch'), qr/200 OK/s, 'fetch tests');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.23.0');

like(http_get('/fetch_multi_header'), qr/200 OK/s,
	'fetch multi header tests');

}

###############################################################################

sub has_version {
	my $need = shift;

	http_get('/njs') =~ /^([.0-9]+)$/m;

	my @v = split(/\./, $1);
	my ($n, $v);

	for $n (split(/\./, $need)) {
		$v = shift @v || 0;
		return 0 if $n > $v;
		return 1 if $v > $n;
	}

	return 1;
}

###############################################################################
