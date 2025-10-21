#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for http response body variable.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ssi njs/)->plan(6);

$t->write_file('utils.js', <<'EOF');
async function trigger_sr(r) {
    const reply = await r.subrequest('/v2');
    r.return(200, "sent_body=<" + reply.variables['sent_body'] + ">\n");
}
export default {trigger_sr}
EOF

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format ubody "sent_body=X${sent_body}X";

    js_import utils.js;

    upstream u {
        server 127.0.0.1:8082;
        server 127.0.0.1:8080 backup;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            access_log %%TESTDIR%%/ubody.log ubody;
        }

        location /ssi.html {
            ssi on;
        }

        location /v {
            proxy_pass http://127.0.0.1:8081;
        }

        location /js {
            js_content utils.trigger_sr;
        }

        location /v2 {
            proxy_pass http://127.0.0.1:8081;
            access_log %%TESTDIR%%/jbody.log ubody;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "TEST";
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 444;
        }
    }
}

EOF

$t->write_file('ssi.html',
	'X<!--#include virtual="/v" -->sent_body=X<!--#echo var="sent_body" -->X');

$t->run();

###############################################################################

like(http_get('/'), qr/200/, "request ok");
is($t->read_file("ubody.log"), "sent_body=XX\n", "empty value in log");
like(http_get('/ssi.html'), qr/XTESTsent_body=XX/, "empty value in SSI");

like(http_get('/js.html'), qr/sent_body=<TEST>/, "subrequest via njs has var");

$t->stop();

my $log = $t->read_file("error.log");

my $warn = 'attempt to use \$sent_body variable when there\'s no response body '
	.'saved in memory';

like($log, qr/$warn while logging request/, "log warning");
like($log, qr/$warn while sending response/, "ssi warning");

###############################################################################
