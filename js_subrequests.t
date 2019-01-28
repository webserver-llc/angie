#!/usr/bin/perl
#
# (C) Dmitry Volyntsev.
# (C) Nginx, Inc.

# Tests for subrequests in http njs module.

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

my $t = Test::Nginx->new()->has(qw/http rewrite proxy cache/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache1
                       keys_zone=ON:1m      use_temp_path=on;

    js_include test.js;

    js_set $async_var async_var;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /njs {
            js_content test_njs;
        }

        location /sr {
            js_content sr;
        }

        location /sr_args {
            js_content sr_args;
        }

        location /sr_options_args {
            js_content sr_options_args;
        }

        location /sr_options_method {
            js_content sr_options_method;
        }

        location /sr_options_body {
            js_content sr_options_body;
        }

        location /sr_options_method_head {
            js_content sr_options_method_head;
        }

        location /sr_body {
            js_content sr_body;
        }

        location /sr_body_special {
            js_content sr_body_special;
        }

        location /sr_background {
            js_content sr_background;
        }

        location /sr_in_variable_handler {
            set $_ $async_var;
            js_content sr_in_variable_handler;
        }

        location /sr_error_page {
            set $_ $async_var;
            error_page 404 /return;
            return 404;
        }

        location /sr_js_in_subrequest {
            js_content sr_js_in_subrequest;
        }

        location /sr_file {
            js_content sr_file;
        }

        location /sr_cache {
            js_content sr_cache;
        }


        location /sr_unavail {
            js_content sr_unavail;
        }

        location /sr_broken {
            js_content sr_broken;
        }

        location /sr_too_large {
            js_content sr_too_large;
        }

        location /sr_out_of_order {
            js_content sr_out_of_order;
        }

        location /sr_except_not_a_func {
            js_content sr_except_not_a_func;
        }

        location /sr_except_failed_to_convert_arg {
            js_content sr_except_failed_to_convert_arg;
        }

        location /sr_except_failed_to_convert_options_arg {
            js_content sr_except_failed_to_convert_options_arg;
        }

        location /sr_except_invalid_options_method {
            js_content sr_except_invalid_options_method;
        }

        location /sr_except_invalid_options_header_only {
            js_content sr_except_invalid_options_header_only;
        }

        location /sr_js_in_sr_parent {
            js_content sr_js_in_sr_parent;
        }

        location /sr_in_sr_callback {
            js_content sr_in_sr_callback;
        }

        location /sr_uri_except {
            js_content sr_uri_except;
        }


        location /file/ {
            alias %%TESTDIR%%/;
        }

        location /p/ {
            proxy_cache $arg_c;
            proxy_pass http://127.0.0.1:8081/;
        }

        location /daemon/ {
            proxy_pass http://127.0.0.1:8082/;
        }

        location /too_large/ {
            subrequest_output_buffer_size 3;
            proxy_pass http://127.0.0.1:8081/;
        }

        location /sr_in_sr {
            js_content sr_in_sr;
        }

        location /unavail {
            proxy_pass http://127.0.0.1:8084/;
        }

        location /sr_parent {
             js_content sr_parent;
        }

        location /js_sub {
            js_content js_sub;
        }

        location /return {
            return 200 '["$request_method"]';
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /sub1 {
            add_header H $arg_h;
            return 206 '{"a": {"b": 1}}';
        }

        location /sub2 {
            return 404 '{"e": "msg"}';
        }

        location /method {
            return 200 '["$request_method"]';
        }

        location /body {
            js_content body;
        }

        location /background {
            js_content background;
        }

        location /delayed {
            js_content delayed;
        }
    }

    server {
        listen       127.0.0.1:8084;
        server_name  localhost;

        return 444;
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function sr(r) {
        subrequest_fn(r, ['/p/sub2'], ['uri', 'status'])
    }

    function sr_args(r) {
        r.subrequest('/p/sub1', 'h=xxx', function(reply) {
            r.status = 200;
            r.sendHeader();
            r.send(JSON.stringify({h:reply.headersOut.h}))
            r.finish();
        });
    }

    function sr_options_args(r) {
        r.subrequest('/p/sub1', {args:'h=xxx'}, function(reply) {
            r.status = 200;
            r.sendHeader();
            r.send(JSON.stringify({h:reply.headersOut.h}))
            r.finish();
        });
    }

    function sr_options_method(r) {
        r.subrequest('/p/method', {method:'POST'}, body_fwd_cb);
    }

    function sr_options_body(r) {
        r.subrequest('/p/body', {method:'POST', body:'["REQ-BODY"]'},
                       body_fwd_cb);
    }

    function sr_options_method_head(r) {
        r.subrequest('/p/method', {method:'HEAD'}, function(reply) {
            r.status = 200;
            r.sendHeader();
            r.send(JSON.stringify({c:reply.status,
                                   s:reply.responseBody.length}))
            r.finish();
        });
    }

    function sr_body(r) {
        r.subrequest('/p/sub1', body_fwd_cb);
    }

    function sr_body_special(r) {
        r.subrequest('/p/sub2', body_fwd_cb);
    }

    function sr_background(r) {
        r.subrequest('/p/background');
        r.subrequest('/p/background', 'a=xxx');
        r.subrequest('/p/background', {args: 'a=yyy', method:'POST'});

        r.status = 200;
        r.sendHeader();
        r.finish();
    }

    function body(r) {
        r.status = 200;
        r.sendHeader();
        r.send(r.variables.request_body);
        r.finish();
    }

    function delayed(r) {
        setTimeout(function(r) {
                        r.status = 200;
                        r.sendHeader();
                        r.finish();
                   }, 100, r);
     }

    function background(r) {
        r.log("BACKGROUND: " + r.variables.request_method
                + " args: " + r.variables.args);

        r.status = 200;
        r.sendHeader();
        r.finish();
    }

    function sr_in_variable_handler(r) {
    }

    function async_var(r) {
        r.subrequest('/p/delayed', function(reply) {
            r.status = 200;
            r.sendHeader();
            r.send(JSON.stringify(["CB-VAR"]))
            r.finish();
        })

        return "";
    }

    function sr_file(r) {
        r.subrequest('/file/t', body_fwd_cb);
    }

    function sr_cache(r) {
        r.subrequest('/p/t', body_fwd_cb);
    }

    function sr_unavail(req) {
        subrequest_fn(req, ['/unavail'], ['uri', 'status']);
    }

    function sr_broken(r) {
        r.subrequest('/daemon/unfinished',
                       function(reply) {
                            r.status = 200;
                            r.sendHeader();
                            r.send(JSON.stringify({code:reply.status}))
                            r.finish();
                        });
    }

    function sr_too_large(r) {
        r.subrequest('/too_large/t', body_fwd_cb);
    }

    function sr_in_sr(r) {
        r.subrequest('/sr', body_fwd_cb);
    }

    function sr_js_in_subrequest(r) {
        r.subrequest('/js_sub', body_fwd_cb);
    }

    function sr_js_in_sr_parent(r) {
        r.subrequest('/sr_parent', body_fwd_cb);
    }

    function sr_in_sr_callback(r) {
        r.subrequest('/return', function (reply) {
                try {
                    reply.subrequest('/return');

                } catch (err) {
                    r.return(200, JSON.stringify({e:err.message}));
                    return;
                }

                r.return(200);
            });
    }

    function sr_parent(r) {
        try {
            var parent = r.parent;

        } catch (err) {
            r.return(200, JSON.stringify({e:err.message}));
            return;
        }

        r.return(200);
    }

    function sr_out_of_order(r) {
        subrequest_fn(r, ['/p/delayed', '/p/sub1', '/unknown'],
                      ['uri', 'status']);
    }

    function subrequest_fn(r, subs, props) {
        var rep, replies = [];

        subs.forEach(function(sr) {
            r.subrequest(sr, function(reply) {
                r.log("subrequest handler: " + reply.uri
                        + " status: " + reply.status)

                rep = {};
                props.forEach(function (p) {rep[p] = reply[p]});

                replies.push(rep);

                if (replies.length == subs.length) {
                    r.status = 200;
                    r.sendHeader();
                    r.send(JSON.stringify(replies));
                    r.finish();
                }
            });
        });
    }

    function sr_except_not_a_func(r) {
        r.subrequest('/sub1', 'a=1', 'b');
    }

    function sr_except_failed_to_convert_arg(r) {
        r.subrequest('/sub1', r.args, function(){});
    }

    function sr_except_failed_to_convert_options_arg(r) {
        r.subrequest('/sub1', {args:r.args}, function(){});
    }

    function sr_except_invalid_options_method(r) {
        r.subrequest('/sub1', {method:'UNKNOWN_METHOD'}, function(){});
    }

    function sr_uri_except(r) {
        r.subrequest(r, 'a=1', 'b');
    }

    function body_fwd_cb(reply) {
        var p = reply.parent;
        p.status = 200;
        p.sendHeader();
        p.send(JSON.stringify(JSON.parse(reply.responseBody)));
        p.finish();
    }

    function js_sub(r) {
        r.status = 200;
        r.sendHeader();
        r.send('["JS-SUB"]');
        r.finish();
    }

EOF

$t->write_file('t', '["SEE-THIS"]');

$t->try_run('no njs available')->plan(25);
$t->run_daemon(\&http_daemon);

###############################################################################

is(get_json('/sr'), '[{"status":404,"uri":"/p/sub2"}]', 'sr');
is(get_json('/sr_args'), '{"h":"xxx"}', 'sr_args');
is(get_json('/sr_options_args'), '{"h":"xxx"}', 'sr_options_args');
is(get_json('/sr_options_method'), '["POST"]', 'sr_options_method');
is(get_json('/sr_options_body'), '["REQ-BODY"]', 'sr_options_body');
is(get_json('/sr_options_method_head'), '{"c":200,"s":0}',
	'sr_options_method_head');
is(get_json('/sr_body'), '{"a":{"b":1}}', 'sr_body');
is(get_json('/sr_body_special'), '{"e":"msg"}', 'sr_body_special');
is(get_json('/sr_in_variable_handler'), '["CB-VAR"]', 'sr_in_variable_handler');
is(get_json('/sr_file'), '["SEE-THIS"]', 'sr_file');
is(get_json('/sr_cache?c=1'), '["SEE-THIS"]', 'sr_cache');
is(get_json('/sr_cache?c=1'), '["SEE-THIS"]', 'sr_cached');
is(get_json('/sr_js_in_subrequest'), '["JS-SUB"]', 'sr_js_in_subrequest');
is(get_json('/sr_unavail'), '[{"status":502,"uri":"/unavail"}]',
	'sr_unavail');
is(get_json('/sr_out_of_order'),
	'[{"status":404,"uri":"/unknown"},' .
	'{"status":206,"uri":"/p/sub1"},' .
	'{"status":200,"uri":"/p/delayed"}]',
	'sr_multi');

http_get('/sr_background');

http_get('/sr_broken');
http_get('/sr_in_sr');
http_get('/sr_in_variable_handler');
http_get('/sr_error_page');
http_get('/sr_too_large');
http_get('/sr_except_not_a_func');
http_get('/sr_except_failed_to_convert_arg');
http_get('/sr_except_failed_to_convert_options_arg');
http_get('/sr_except_invalid_options_method');
http_get('/sr_uri_except');

TODO: {
local $TODO = 'not yet'
	unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.2.4';

is(get_json('/sr_js_in_sr_parent'),
	'{"e":"parent can only be returned for a subrequest"}',
	'parent in subrequest js_content');

todo_skip 'leaves coredump', 1
	unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.2.4';

is(get_json('/sr_in_sr_callback'),
	'{"e":"subrequest can only be created for the primary request"}',
	'subrequest for non-primary request');

}

$t->stop();

ok(index($t->read_file('error.log'), 'callback is not a function') > 0,
	'subrequest cb exception');
ok(index($t->read_file('error.log'), 'failed to convert uri arg') > 0,
	'subrequest uri exception');
ok(index($t->read_file('error.log'), 'failed to convert args') > 0,
	'subrequest invalid args exception');
ok(index($t->read_file('error.log'), 'unknown method "UNKNOWN_METHOD"') > 0,
	'subrequest unknown method exception');
ok(index($t->read_file('error.log'), 'BACKGROUND') > 0,
	'background subrequest');
ok(index($t->read_file('error.log'), 'too big subrequest response') > 0,
	'subrequest too large body');
ok(index($t->read_file('error.log'), 'subrequest creation failed') > 0,
	'subrequest creation failed');
ok(index($t->read_file('error.log'),
		'js subrequest: failed to get the parent context') > 0,
	'zero parent ctx');

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

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port(8082),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/unfinished') {
			print $client
				"HTTP/1.1 200 OK" . CRLF .
				"Transfer-Encoding: chunked" . CRLF .
				"Content-Length: 100" . CRLF .
				CRLF .
				"unfinished" . CRLF;
			close($client);
		}
	}
}

###############################################################################
