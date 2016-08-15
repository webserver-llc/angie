#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream JavaScript module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ dgram stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return udp/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    js_set $js_addr      js_addr;
    js_set $js_var       js_var;
    js_set $js_log       js_log;
    js_set $js_unk       js_unk;
    js_set $js_sess_unk  js_sess_unk;

    js_include functions.js;

    server {
        listen  127.0.0.1:8080;
        return  $js_addr;
    }

    server {
        listen  127.0.0.1:8081;
        return  $js_log;
    }

    server {
        listen  127.0.0.1:8082;
        return  $js_var;
    }

    server {
        listen  127.0.0.1:8083;
        return  $js_unk;
    }

    server {
        listen  127.0.0.1:8084;
        return  $js_sess_unk;
    }

    server {
        listen  127.0.0.1:%%PORT_8085_UDP%% udp;
        return  $js_addr;
    }
}

EOF

$t->write_file('functions.js', <<EOF);
    function js_addr(sess) {
        return 'addr=' + sess.remoteAddress;
    }

    function js_var(sess) {
        return 'variable=' + sess.variables.remote_addr;
    }

    function js_sess_unk(sess) {
        return 'sess_unk=' + sess.unk;
    }

    function js_log(sess) {
        sess.log("SEE-THIS");
    }
EOF

$t->try_run('no stream njs available')->plan(7);

###############################################################################

is(stream('127.0.0.1:' . port(8080))->read(), 'addr=127.0.0.1',
	'sess.remoteAddress');
is(dgram('127.0.0.1:' . port(8085))->io('.'), 'addr=127.0.0.1',
	'sess.remoteAddress udp');
is(stream('127.0.0.1:' . port(8081))->read(), 'undefined', 'sess.log');
is(stream('127.0.0.1:' . port(8082))->read(), 'variable=127.0.0.1',
	'sess.variables');
is(stream('127.0.0.1:' . port(8083))->read(), '', 'stream js unknown function');
is(stream('127.0.0.1:' . port(8084))->read(), 'sess_unk=undefined', 'sess.unk');

$t->stop();

ok(index($t->read_file('error.log'), 'SEE-THIS') > 0, 'stream js log');

###############################################################################
