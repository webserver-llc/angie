#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream proxy module with IPv6 haproxy protocol.

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

my $t = Test::Nginx->new()->has(qw/http proxy stream ipv6/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen          127.0.0.1:8080;
        server_name     localhost;

        location /on {
            proxy_pass  http://[::1]:8080;
        }

        location /off {
            proxy_pass  http://[::1]:8081;
        }
    }
}

stream {
    proxy_protocol on;

    server {
        listen          [::1]:8080;
        proxy_pass      127.0.0.1:8082;
    }

    server {
        listen          [::1]:8081;
        proxy_pass      127.0.0.1:8082;
        proxy_protocol  off;
    }
}

EOF

$t->run_daemon(\&stream_daemon);
$t->try_run('no inet6 support')->plan(2);
$t->waitforsocket('127.0.0.1:8082');

###############################################################################

like(http_get('/on'), qr/PROXY TCP6 ::1 ::1 [0-9]+ 8080/, 'protocol on');
unlike(http_get('/off'), qr/PROXY/, 'protocol off');

###############################################################################

sub stream_daemon {
	my $d = shift;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:8082',
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

		$buffer =~ /(.*?)\x0d\x0a?/ms;
		$buffer = $1;

		log2o("$client $buffer");

		$client->syswrite($buffer);

		close $client;
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
