#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http njs module, internalRedirect method.

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

    js_include test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /njs {
            js_content test_njs;
        }

        location /test {
            js_content test_redirect;
        }

        location /redirect {
            internal;
            return 200 redirect$arg_b;
        }

        location @named {
            return 200 named;
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function test_redirect(r) {
        if (r.variables.arg_dest == 'named') {
            r.internalRedirect('\@named');

        } else {
            if (r.variables.arg_a) {
                r.internalRedirect('/redirect?b=' + r.variables.arg_a);

            } else {
                r.internalRedirect('/redirect');
            }
        }
    }

EOF

$t->try_run('no njs available')->plan(3);

###############################################################################

like(http_get('/test'), qr/redirect/s, 'redirect');
like(http_get('/test?a=A'), qr/redirectA/s, 'redirect with args');
like(http_get('/test?dest=named'), qr/named/s, 'redirect to named location');

###############################################################################
