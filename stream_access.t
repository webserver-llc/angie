#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream access module.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_access ipv6/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    server {
        listen       127.0.0.1:8082;
        proxy_pass   [::1]:8080;
    }

    server {
        listen       127.0.0.1:8083;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.0;
    }

    server {
        listen       127.0.0.1:8085;
        proxy_pass   [::1]:8081;
    }

    server {
        listen       127.0.0.1:8086;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.1;
    }

    server {
        listen       127.0.0.1:8088;
        proxy_pass   [::1]:8082;
    }

    server {
        listen       127.0.0.1:8089;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.2;
    }

    server {
        listen       127.0.0.1:8091;
        proxy_pass   [::1]:8083;
    }

    server {
        listen       127.0.0.1:8092;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.3;
    }

    server {
        listen       127.0.0.1:8094;
        proxy_pass   [::1]:8084;
    }

    server {
        listen       127.0.0.1:8095;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.4;
    }

    server {
        listen       127.0.0.1:8097;
        proxy_pass   [::1]:8085;
    }

    server {
        listen       127.0.0.1:8098;
        proxy_pass   unix:%%TESTDIR%%/unix.sock.5;
    }

    server {
        listen       127.0.0.1:8081;
        listen       [::1]:8080;
        listen       unix:%%TESTDIR%%/unix.sock.0;
        proxy_pass   127.0.0.1:8080;
        allow        all;
    }

    server {
        listen       127.0.0.1:8084;
        listen       [::1]:8081;
        listen       unix:%%TESTDIR%%/unix.sock.1;
        proxy_pass   127.0.0.1:8080;
        deny         all;
    }

    server {
        listen       127.0.0.1:8087;
        listen       [::1]:8082;
        listen       unix:%%TESTDIR%%/unix.sock.2;
        proxy_pass   127.0.0.1:8080;
        allow        unix:;
    }

    server {
        listen       127.0.0.1:8090;
        listen       [::1]:8083;
        listen       unix:%%TESTDIR%%/unix.sock.3;
        proxy_pass   127.0.0.1:8080;
        deny         127.0.0.1;
    }

    server {
        listen       127.0.0.1:8093;
        listen       [::1]:8084;
        listen       unix:%%TESTDIR%%/unix.sock.4;
        proxy_pass   127.0.0.1:8080;
        deny         ::1;
    }

    server {
        listen       127.0.0.1:8096;
        listen       [::1]:8085;
        listen       unix:%%TESTDIR%%/unix.sock.5;
        proxy_pass   127.0.0.1:8080;
        deny         unix:;
    }
}

EOF

$t->run_daemon(\&stream_daemon);
$t->try_run('no inet6 and/or unix support')->plan(18);
$t->waitforsocket('127.0.0.1:8080');

###############################################################################

my $str = 'SEE-THIS';

# allow all

is(stream_get($str, '127.0.0.1:8081'), $str, 'inet allow all');
is(stream_get($str, '127.0.0.1:8082'), $str, 'inet6 allow all');
is(stream_get($str, '127.0.0.1:8083'), $str, 'unix allow all');

# deny all

is(stream_get($str, '127.0.0.1:8084'), '', 'inet deny all');
is(stream_get($str, '127.0.0.1:8085'), '', 'inet6 deny all');
is(stream_get($str, '127.0.0.1:8086'), '', 'unix deny all');

# allow unix

is(stream_get($str, '127.0.0.1:8087'), $str, 'inet allow unix');
is(stream_get($str, '127.0.0.1:8088'), $str, 'inet6 allow unix');
is(stream_get($str, '127.0.0.1:8089'), $str, 'unix allow unix');

# deny inet

is(stream_get($str, '127.0.0.1:8090'), '', 'inet deny inet');
is(stream_get($str, '127.0.0.1:8091'), $str, 'inet6 deny inet');
is(stream_get($str, '127.0.0.1:8092'), $str, 'unix deny inet');

# deny inet6

is(stream_get($str, '127.0.0.1:8093'), $str, 'inet deny inet6');
is(stream_get($str, '127.0.0.1:8094'), '', 'inet6 deny inet6');
is(stream_get($str, '127.0.0.1:8095'), $str, 'unix deny inet6');

# deny unix

is(stream_get($str, '127.0.0.1:8096'), $str, 'inet deny unix');
is(stream_get($str, '127.0.0.1:8097'), $str, 'inet6 deny unix');
is(stream_get($str, '127.0.0.1:8098'), '', 'unix deny unix');

###############################################################################

sub stream_get {
	my ($data, $peer) = @_;

	my $s = stream_connect($peer);
	stream_write($s, $data);

	$data = '';
	while (my $buf = stream_read($s)) {
		$data .= $buf;
	}

	return $data;
}

sub stream_connect {
	my $peer = shift;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => $peer || '127.0.0.1:8080'
	)
		or die "Can't connect to nginx: $!\n";

	return $s;
}

sub stream_write {
	my ($s, $message) = @_;

	local $SIG{PIPE} = 'IGNORE';

	$s->blocking(0);
	while (IO::Select->new($s)->can_write(1.5)) {
		my $n = $s->syswrite($message);
		last unless $n;
		$message = substr($message, $n);
		last unless length $message;
	}

	if (length $message) {
		$s->close();
	}
}

sub stream_read {
	my ($s) = @_;
	my ($buf);

	$s->blocking(0);
	if (IO::Select->new($s)->can_read(3)) {
		$s->sysread($buf, 1024);
	};

	log_in($buf);
	return $buf;
}

###############################################################################

sub stream_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:8080',
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
