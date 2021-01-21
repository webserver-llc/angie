#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for stream njs module, fetch method.

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

my $t = Test::Nginx->new()->has(qw/http stream/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    js_import test.js;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /njs {
            js_content test.njs;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  aaa;

        location /validate {
            js_content test.validate;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    js_import test.js;

    server {
        listen      127.0.0.1:8081;
        js_preread  test.preread_verify;
        proxy_pass  127.0.0.1:8090;
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function validate(r) {
        r.return((r.requestText == 'QZ') ? 200 : 403);
    }

    function preread_verify(s) {
        var collect = Buffer.from([]);

        s.on('upstream', function (data, flags) {
            collect = Buffer.concat([collect, data]);

            if (collect.length >= 4 && collect.readUInt16BE(0) == 0xabcd) {
                s.off('upstream');
                ngx.fetch('http://127.0.0.1:8080/validate',
                          {body: collect.slice(2,4), headers: {Host:'aaa'}})
                .then(reply => (reply.status == 200) ? s.done(): s.deny())

            } else if (collect.length) {
                s.deny();
            }
        });
    }

    export default {njs: test_njs, validate, preread_verify}
EOF

$t->try_run('no stream njs available')->plan(4);

$t->run_daemon(\&stream_daemon, port(8090));
$t->waitforsocket('127.0.0.1:' . port(8090));

###############################################################################

local $TODO = 'not yet'
	unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.5.1';

is(stream('127.0.0.1:' . port(8081))->io('###'), '', 'preread not enough');
is(stream('127.0.0.1:' . port(8081))->io("\xAB\xCDQZ##"), "\xAB\xCDQZ##",
	'preread validated');
is(stream('127.0.0.1:' . port(8081))->io("\xAC\xCDQZ##"), '',
	'preread invalid magic');
is(stream('127.0.0.1:' . port(8081))->io("\xAB\xCDQQ##"), '',
	'preread validation failed');

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
