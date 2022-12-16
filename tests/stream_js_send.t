#!/usr/bin/perl

# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for s.send() in stream njs module.

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
}

stream {
    %%TEST_GLOBALS_STREAM%%

    js_import test.js;

    server {
        listen      127.0.0.1:8081;
        js_filter   test.filter;
        proxy_pass  127.0.0.1:8090;
    }

    server {
        listen      127.0.0.1:8082;
        js_filter   test.filter_direct;
        proxy_pass  127.0.0.1:8090;
    }
}

EOF

$t->write_file('test.js', <<EOF);
    function test_njs(r) {
        r.return(200, njs.version);
    }

    function filter(s) {
      s.on("upload", async (data, flags) => {
        s.send("__HANDSHAKE__", flags);

        const p = new Promise((resolve, reject) => {
              s.on("download", (data, flags) => {
                  s.off("download");
                  resolve(data);
              });
        });

        s.off("upload");

        const handshakeResponse = await p;
        if (handshakeResponse != '__HANDSHAKE_RESPONSE__') {
            throw `Handshake failed: \${handshakeResponse}`;
        }

        s.send(data, flags);
      });
    }

    function filter_direct(s) {
      s.on("upload", async (data, flags) => {
        s.sendUpstream("__HANDSHAKE__", flags);

        const p = new Promise((resolve, reject) => {
              s.on("download", (data, flags) => {
                  s.off("download");
                  resolve(data);
              });
        });

        s.off("upload");

        const handshakeResponse = await p;
        if (handshakeResponse != '__HANDSHAKE_RESPONSE__') {
            throw `Handshake failed: \${handshakeResponse}`;
        }

        s.sendDownstream('xxx', flags);
        s.sendUpstream(data, flags);
      });
    }

    export default {njs:test_njs, filter, filter_direct};

EOF

$t->run_daemon(\&stream_daemon, port(8090));
$t->try_run('no stream njs available')->plan(2);
$t->waitforsocket('127.0.0.1:' . port(8090));

###############################################################################

is(stream('127.0.0.1:' . port(8081))->io('abc'), 'ABC',
	'async filter');;
is(stream('127.0.0.1:' . port(8082))->io('abc'), 'xxxABC',
	'async filter direct');

$t->stop();

###############################################################################

sub has_version {
	my $need = shift;

	http_get('/njs') =~ /^([.0-9]+)$/m;

	my @v = split(/\./, $1);
	my ($n, $v);

	for $n (split(/\./, $need)) {
		$v = shift @v || 0;
		return 0 if $n > $v;
		return 1 if $v > $n;
	}

	return 1;
}

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

		if ($buffer ne "__HANDSHAKE__") {
			$buffer = "__HANDSHAKE_INVALID__";
			log2o("$client $buffer");
			$client->syswrite($buffer);

			close $client;
		}

		$buffer = "__HANDSHAKE_RESPONSE__";
		log2o("$client $buffer");
		$client->syswrite($buffer);

		$client->sysread($buffer, 65536) or next;

		$buffer = uc($buffer);
		log2o("$client $buffer");
		$client->syswrite($buffer);

		close $client;
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
