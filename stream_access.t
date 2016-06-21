#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream access module.

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

my $t = Test::Nginx->new()->has(qw/stream stream_access ipv6 unix/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    server {
        listen       127.0.0.1:%%PORT_2%%;
        proxy_pass   [::1]:%%PORT_0%%;
    }

    server {
        listen       127.0.0.1:%%PORT_3%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.0;
    }

    server {
        listen       127.0.0.1:%%PORT_5%%;
        proxy_pass   [::1]:%%PORT_1%%;
    }

    server {
        listen       127.0.0.1:%%PORT_6%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.1;
    }

    server {
        listen       127.0.0.1:%%PORT_8%%;
        proxy_pass   [::1]:%%PORT_2%%;
    }

    server {
        listen       127.0.0.1:%%PORT_9%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.2;
    }

    server {
        listen       127.0.0.1:%%PORT_11%%;
        proxy_pass   [::1]:%%PORT_3%%;
    }

    server {
        listen       127.0.0.1:%%PORT_12%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.3;
    }

    server {
        listen       127.0.0.1:%%PORT_14%%;
        proxy_pass   [::1]:%%PORT_4%%;
    }

    server {
        listen       127.0.0.1:%%PORT_15%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.4;
    }

    server {
        listen       127.0.0.1:%%PORT_17%%;
        proxy_pass   [::1]:%%PORT_5%%;
    }

    server {
        listen       127.0.0.1:%%PORT_18%%;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.5;
    }

    server {
        listen       127.0.0.1:%%PORT_1%%;
        listen       [::1]:%%PORT_0%%;
        listen       unix:%%TESTDIR%%/unix.sock.0;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        allow        all;
    }

    server {
        listen       127.0.0.1:%%PORT_4%%;
        listen       [::1]:%%PORT_1%%;
        listen       unix:%%TESTDIR%%/unix.sock.1;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        deny         all;
    }

    server {
        listen       127.0.0.1:%%PORT_7%%;
        listen       [::1]:%%PORT_2%%;
        listen       unix:%%TESTDIR%%/unix.sock.2;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        allow        unix:;
    }

    server {
        listen       127.0.0.1:%%PORT_10%%;
        listen       [::1]:%%PORT_3%%;
        listen       unix:%%TESTDIR%%/unix.sock.3;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        deny         127.0.0.1;
    }

    server {
        listen       127.0.0.1:%%PORT_13%%;
        listen       [::1]:%%PORT_4%%;
        listen       unix:%%TESTDIR%%/unix.sock.4;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        deny         ::1;
    }

    server {
        listen       127.0.0.1:%%PORT_16%%;
        listen       [::1]:%%PORT_5%%;
        listen       unix:%%TESTDIR%%/unix.sock.5;
        proxy_pass   127.0.0.1:%%PORT_0%%;
        deny         unix:;
    }
}

EOF

$t->try_run('no inet6 support')->plan(18);
$t->run_daemon(\&stream_daemon);
$t->waitforsocket('127.0.0.1:' . port(0));

###############################################################################

my $str = 'SEE-THIS';

# allow all

is(stream('127.0.0.1:' . port(1))->io($str), $str, 'inet allow all');
is(stream('127.0.0.1:' . port(2))->io($str), $str, 'inet6 allow all');
is(stream('127.0.0.1:' . port(3))->io($str), $str, 'unix allow all');

# deny all

is(stream('127.0.0.1:' . port(4))->io($str), '', 'inet deny all');
is(stream('127.0.0.1:' . port(5))->io($str), '', 'inet6 deny all');
is(stream('127.0.0.1:' . port(6))->io($str), '', 'unix deny all');

# allow unix

is(stream('127.0.0.1:' . port(7))->io($str), $str, 'inet allow unix');
is(stream('127.0.0.1:' . port(8))->io($str), $str, 'inet6 allow unix');
is(stream('127.0.0.1:' . port(9))->io($str), $str, 'unix allow unix');

# deny inet

is(stream('127.0.0.1:' . port(10))->io($str), '', 'inet deny inet');
is(stream('127.0.0.1:' . port(11))->io($str), $str, 'inet6 deny inet');
is(stream('127.0.0.1:' . port(12))->io($str), $str, 'unix deny inet');

# deny inet6

is(stream('127.0.0.1:' . port(13))->io($str), $str, 'inet deny inet6');
is(stream('127.0.0.1:' . port(14))->io($str), '', 'inet6 deny inet6');
is(stream('127.0.0.1:' . port(15))->io($str), $str, 'unix deny inet6');

# deny unix

is(stream('127.0.0.1:' . port(16))->io($str), $str, 'inet deny unix');
is(stream('127.0.0.1:' . port(17))->io($str), $str, 'inet6 deny unix');
is(stream('127.0.0.1:' . port(18))->io($str), '', 'unix deny unix');

###############################################################################

sub stream_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port(0),
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
