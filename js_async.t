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
    function set_timeout(req, res) {
        var timerId = setTimeout(timeout_cb_r, 5, req, res, 0);
        clearTimeout(timerId);
        setTimeout(timeout_cb_r, 5, req, res, 0)
    }

    function set_timeout_data(req, res) {
        setTimeout(timeout_cb_data, 5, req, res, 0);
    }

    function set_timeout_many(req, res) {
        for (var i = 0; i < 5; i++) {
            setTimeout(timeout_cb_empty, 5, req, i);
        }

        setTimeout(timeout_cb_reply, 10, res);
    }

    function timeout_cb_r(req, res, cnt) {
        if (cnt == 10) {
            res.status = 200;
            res.contentType = 'foo';
            res.sendHeader();
            res.finish();

        } else {
            setTimeout(timeout_cb_r, 5, req, res, ++cnt);
        }
    }

    function timeout_cb_empty(req, arg) {
        req.log("timeout_cb_empty" + arg);
    }

    function timeout_cb_reply(res) {
        res.status = 200;
        res.contentType = 'reply';
        res.sendHeader();
        res.finish();
    }

    function timeout_cb_data(req, res, counter) {
        if (counter == 0) {
            req.log("timeout_cb_data: init");
            res.status = 200;
            res.sendHeader();
            setTimeout(timeout_cb_data, 5, req, res, ++counter);

        } else if (counter == 10) {
            req.log("timeout_cb_data: finish");
            res.finish();

        } else {
            res.send("" + counter);
            setTimeout(timeout_cb_data, 5, req, res, ++counter);
        }
    }

    var js_;
    function context_var() {
        return js_;
    }

    function shared_ctx(req, res) {
        js_ = req.variables.arg_a;

        res.status = 200;
        res.sendHeader();
        res.finish();
    }

    function limit_rate_cb(res) {
        res.finish();
    }

    function limit_rate(req, res) {
        res.status = 200;
        res.sendHeader();
        res.send("AAAAA".repeat(10))
        setTimeout(limit_rate_cb, 1000, res);
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
