#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http njs module, working with headers.

###############################################################################

use warnings;
use strict;

use Test::More;

use Config;

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

EOF

$t->try_run('no njs')->plan(5);

###############################################################################


TODO: {
local $TODO = 'not yet'
		unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.2.8';

like(http_get('/content_length'), qr/Content-Length: 3/,
	'set Content-Length');
like(http_get('/content_type'), qr/Content-Type: text\/xml; charset="utf-8"\r/,
	'set Content-Type');
unlike(http_get('/content_type'), qr/Content-Type: text\/plain/,
	'set Content-Type 2');
like(http_get('/content_encoding'), qr/Content-Encoding: gzip/,
	'set Content-Encoding');
like(http_get('/headers_list'), qr/a:c:d/, 'headers list');

}

###############################################################################
