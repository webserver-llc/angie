#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for stream njs module, Response prototype reinitialization.

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

my $t = Test::Nginx->new()->has(qw/http rewrite stream/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    js_import test.js;

    server {
        listen      127.0.0.1:8081;
        js_access   test.access_ok;
        proxy_pass  127.0.0.1:8090;
    }
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

        location /success {
            return 200;
        }
    }
}

EOF

my $p = port(8080);

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    async function access_ok(s) {
        let reply = await ngx.fetch('http://127.0.0.1:$p/success',
                                    {headers: {Host:'aaa'}});

        (reply.status == 200) ? s.allow(): s.deny();
    }

    export default {njs: test_njs, access_ok};
EOF

$t->try_run('no stream njs available')->plan(1);

$t->run_daemon(\&stream_daemon, port(8090));
$t->waitforsocket('127.0.0.1:' . port(8090));

###############################################################################

local $TODO = 'not yet'
	unless http_get('/njs') =~ /^([.0-9]+)$/m && $1 ge '0.7.9';

is(stream('127.0.0.1:' . port(8081))->io('ABC'), 'ABC', 'access fetch ok');

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
