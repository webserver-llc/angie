#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http njs module, return method.

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

my $t = Test::Nginx->new()->has(qw/http/)
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

        location / {
            js_content test_return;
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function test_return(r) {
        r.return(Number(r.args.c), r.args.t);
    }

EOF

$t->try_run('no njs return')->plan(5);

###############################################################################

like(http_get('/?c=200'), qr/200 OK.*\x0d\x0a?\x0d\x0a?$/s, 'return code');
like(http_get('/?c=200&t=SEE-THIS'), qr/200 OK.*^SEE-THIS$/ms, 'return text');
like(http_get('/?c=301&t=path'), qr/ 301 .*Location: path/s, 'return redirect');
like(http_get('/?c=404'), qr/404 Not.*html/s, 'return error page');

TODO: {
my ($v) = http_get('/njs') =~ /^([.0-9]+)$/m;
local $TODO = 'not yet' unless $Config{archname} !~ /aarch64/;

like(http_get('/?c=inv'), qr/ 500 /, 'return invalid');

}

###############################################################################
