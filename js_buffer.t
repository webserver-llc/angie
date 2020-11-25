#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http njs module, buffer properties.

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

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy/)
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

        location /return {
            js_content test.return;
        }

        location /req_body {
            js_content test.req_body;
        }

        location /res_body {
            js_content test.res_body;
        }

        location /binary_var {
            js_content test.binary_var;
        }

        location /p/ {
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /sub1 {
            return 200 '{"a": {"b": 1}}';
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function test_return(r) {
        var body = Buffer.from("body: ");
        body = Buffer.concat([body, Buffer.from(r.args.text)]);
        r.return(200, body);
    }

    function req_body(r) {
        var body = r.reqBody;
        var view = new DataView(body.buffer);
        view.setInt8(2, 'c'.charCodeAt(0));
        r.return(200, JSON.parse(body).c.b);
    }

    function res_body(r) {
        r.subrequest('/p/sub1')
        .then(reply => {
            var body = reply.resBody;
            var view = new DataView(body.buffer);
            view.setInt8(2, 'c'.charCodeAt(0));
            r.return(200, JSON.stringify(JSON.parse(body)));
        })
    }

    function binary_var(r) {
        var test = r.vars.binary_remote_addr.equals(Buffer.from([127,0,0,1]));
        r.return(200, test);
    }

    export default {njs: test_njs, return: test_return, req_body, res_body,
	                binary_var};

EOF

$t->try_run('no njs buffer')->plan(4);

###############################################################################

TODO: {
local $TODO = 'not yet'
	unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.5.0';

like(http_get('/return?text=FOO'), qr/200 OK.*body: FOO$/s,
	'return buffer');
like(http_post('/req_body'), qr/200 OK.*BAR$/s, 'req body');
is(get_json('/res_body'), '{"c":{"b":1}}', 'res body');
like(http_get('/binary_var'), qr/200 OK.*true$/s,
	'binary var');

}

###############################################################################

sub recode {
	my $json;
	eval { $json = JSON::PP::decode_json(shift) };

	if ($@) {
		return "<failed to parse JSON>";
	}

	JSON::PP->new()->canonical()->encode($json);
}

sub get_json {
	http_get(shift) =~ /\x0d\x0a?\x0d\x0a?(.*)/ms;
	recode($1);
}

sub http_post {
	my ($url, %extra) = @_;

	my $p = "POST $url HTTP/1.0" . CRLF .
		"Host: localhost" . CRLF .
		"Content-Length: 17" . CRLF .
		CRLF .
		"{\"a\":{\"b\":\"BAR\"}}";

	return http($p, %extra);
}

###############################################################################
