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

    js_include test.js;

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
        listen  127.0.0.1:%%PORT_8985_UDP%% udp;
        return  $js_addr;
    }

    server {
        listen      127.0.0.1:8086;
        js_access   js_access_allow;
        return      'OK';
    }

    server {
        listen      127.0.0.1:8087;
        js_access   js_access_deny;
        return      'OK';
    }

    server {
        listen      127.0.0.1:8088;
        js_preread  js_preread;
        proxy_pass  127.0.0.1:8090;
    }

    server {
        listen      127.0.0.1:8089;
        js_filter   js_filter;
        proxy_pass  127.0.0.1:8090;
    }

    server {
        listen      127.0.0.1:8091;
        js_access   js_access_step;
        js_preread  js_preread_step;
        js_filter   js_filter_step;
        proxy_pass  127.0.0.1:8090;
    }

    server {
        listen      127.0.0.1:8092;
        js_filter   js_filter_except;
        proxy_pass  127.0.0.1:8090;
    }

    server {
        listen      127.0.0.1:8093;
        js_preread  js_preread_except;
        proxy_pass  127.0.0.1:8090;
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function js_addr(s) {
        return 'addr=' + s.remoteAddress;
    }

    function js_var(s) {
        return 'variable=' + s.variables.remote_addr;
    }

    function js_sess_unk(s) {
        return 'sess_unk=' + s.unk;
    }

    function js_log(s) {
        s.log("SEE-THIS");
    }

    function js_access_allow(s) {
        if (s.remoteAddress.match('127.0.0.1')) {
            return s.OK;
        }
    }

    function js_access_deny(s) {
        if (s.remoteAddress.match('127.0.0.1')) {
            return s.ABORT;
        }
    }

    function js_preread(s) {
        var n = s.buffer.indexOf('z');
        if (n == -1) {
            return s.AGAIN;
        }
    }

    function js_filter(s) {
        if (s.fromUpstream) {
            var n = s.buffer.search('y');
            if (n != -1) {
                s.buffer = 'z';
            }
            return;
        }

        n = s.buffer.search('x');
        if (n != -1) {
            s.buffer = 'y';
        }
    }

    var res = '';
    function js_access_step(s) {
        res += '1';
    }

    function js_preread_step(s) {
        res += '2';
    }

    function js_filter_step(s) {
        if (s.eof) {
            s.buffer = res;
            return;
        }
        res += '3';
    }

    function js_preread_except(s) {
        var fs = require('fs');
        fs.readFileSync();
    }

    function js_filter_except(s) {
        s.a.a;
    }

EOF

$t->run_daemon(\&stream_daemon, port(8090));
$t->try_run('no stream njs available')->plan(14);
$t->waitforsocket('127.0.0.1:' . port(8090));

###############################################################################

is(stream('127.0.0.1:' . port(8080))->read(), 'addr=127.0.0.1',
	's.remoteAddress');
is(dgram('127.0.0.1:' . port(8985))->io('.'), 'addr=127.0.0.1',
	's.remoteAddress udp');
is(stream('127.0.0.1:' . port(8081))->read(), 'undefined', 's.log');
is(stream('127.0.0.1:' . port(8082))->read(), 'variable=127.0.0.1',
	's.variables');
is(stream('127.0.0.1:' . port(8083))->read(), '', 'stream js unknown function');
is(stream('127.0.0.1:' . port(8084))->read(), 'sess_unk=undefined', 's.unk');

is(stream('127.0.0.1:' . port(8086))->read(), 'OK', 'js_access allow');
is(stream('127.0.0.1:' . port(8087))->read(), '', 'js_access deny');
is(stream('127.0.0.1:' . port(8088))->io('xyz'), 'xyz', 'js_preread');
is(stream('127.0.0.1:' . port(8089))->io('x'), 'z', 'js_filter');
is(stream('127.0.0.1:' . port(8091))->io('0'), '01233', 'handlers order');

stream('127.0.0.1:' . port(8092))->io('x');
stream('127.0.0.1:' . port(8093))->io('x');

$t->stop();

ok(index($t->read_file('error.log'), 'SEE-THIS') > 0, 'stream js log');
ok(index($t->read_file('error.log'), 'at fs.readFileSync') > 0,
   'stream js_preread backtrace');
ok(index($t->read_file('error.log'), 'at js_filter_except') > 0,
   'stream js_filter backtrace');

###############################################################################

sub stream_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port(8090),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		log2c("(new connection $client)");

		$client->sysread(my $buffer, 65536) or next;

		log2i("$client $buffer");

		log2o("$client $buffer");

		$client->syswrite($buffer);

		close $client;
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
