#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for stream njs module, setting nginx variables.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http stream stream_return/)
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
    }
}

stream {
    js_set $test_var       test_var;
    js_set $test_not_found test_not_found;

    js_include test.js;

    server {
        listen  127.0.0.1:8081;
        return  $test_var$status;
    }

    server {
        listen  127.0.0.1:8082;
        return  $test_not_found;
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function test_var(s) {
        s.variables.status = 400;
        return 'test_var';
    }

    function test_not_found(s) {
        try {
            s.variables.unknown = 1;
        } catch (e) {
            return 'not_found';
        }
    }

EOF

$t->try_run('no stream njs available')->plan(2);

###############################################################################

is(stream('127.0.0.1:' . port(8081))->read(), 'test_var400', 'var set');
is(stream('127.0.0.1:' . port(8082))->read(), 'not_found', 'not found set');

$t->stop();

###############################################################################
