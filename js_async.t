#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Async tests for http njs module.

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

    js_set $test_async      set_timeout;
    js_set $context_var     context_var;

    js_include test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /async_var {
            return 200 $test_async;
        }

        location /shared_ctx {
            add_header H $context_var;
            js_content shared_ctx;
        }

        location /set_timeout {
            js_content set_timeout;
        }

        location /set_timeout_many {
            js_content set_timeout_many;
        }

        location /set_timeout_data {
            postpone_output 0;
            js_content set_timeout_data;
        }

        location /limit_rate {
            postpone_output 0;
            sendfile_max_chunk 5;
            js_content limit_rate;
        }
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function set_timeout(r) {
        var timerId = setTimeout(timeout_cb_r, 5, r, 0);
        clearTimeout(timerId);
        setTimeout(timeout_cb_r, 5, r, 0)
    }

    function set_timeout_data(r) {
        setTimeout(timeout_cb_data, 5, r, 0);
    }

    function set_timeout_many(r) {
        for (var i = 0; i < 5; i++) {
            setTimeout(timeout_cb_empty, 5, r, i);
        }

        setTimeout(timeout_cb_reply, 10, r);
    }

    function timeout_cb_r(r, cnt) {
        if (cnt == 10) {
            r.status = 200;
            r.headersOut['Content-Type'] = 'foo';
            r.sendHeader();
            r.finish();

        } else {
            setTimeout(timeout_cb_r, 5, r, ++cnt);
        }
    }

    function timeout_cb_empty(r, arg) {
        r.log("timeout_cb_empty" + arg);
    }

    function timeout_cb_reply(r) {
        r.status = 200;
        r.headersOut['Content-Type'] = 'reply';
        r.sendHeader();
        r.finish();
    }

    function timeout_cb_data(r, counter) {
        if (counter == 0) {
            r.log("timeout_cb_data: init");
            r.status = 200;
            r.sendHeader();
            setTimeout(timeout_cb_data, 5, r, ++counter);

        } else if (counter == 10) {
            r.log("timeout_cb_data: finish");
            r.finish();

        } else {
            r.send("" + counter);
            setTimeout(timeout_cb_data, 5, r, ++counter);
        }
    }

    var js_;
    function context_var() {
        return js_;
    }

    function shared_ctx(r) {
        js_ = r.variables.arg_a;

        r.status = 200;
        r.sendHeader();
        r.finish();
    }

    function limit_rate_cb(r) {
        r.finish();
    }

    function limit_rate(r) {
        r.status = 200;
        r.sendHeader();
        r.send("AAAAA".repeat(10))
        setTimeout(limit_rate_cb, 1000, r);
    }

EOF

$t->try_run('no njs available')->plan(7);

###############################################################################

like(http_get('/set_timeout'), qr/Content-Type: foo/, 'setTimeout');
like(http_get('/set_timeout_many'), qr/Content-Type: reply/, 'setTimeout many');
like(http_get('/set_timeout_data'), qr/123456789/, 'setTimeout data');
like(http_get('/shared_ctx?a=xxx'), qr/H: xxx/, 'shared context');
like(http_get('/limit_rate'), qr/A{50}/, 'limit_rate');

http_get('/async_var');

$t->stop();

ok(index($t->read_file('error.log'), 'pending events') > 0,
   'pending js events');
ok(index($t->read_file('error.log'), 'async operation inside') > 0,
   'async op in var handler');

###############################################################################
