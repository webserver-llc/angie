#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream proxy module, proxy_next_upstream directive and friends.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    upstream u {
        server 127.0.0.1:8087 max_fails=0;
        server 127.0.0.1:8088 max_fails=0;
        server 127.0.0.1:8089 backup;
    }

    proxy_connect_timeout 1s;

    server {
        listen      127.0.0.1:8081;
        proxy_pass  u;
        proxy_next_upstream off;
    }

    server {
        listen      127.0.0.1:8082;
        proxy_pass  u;
        proxy_next_upstream on;
    }

    server {
        listen      127.0.0.1:8083;
        proxy_pass  u;
        proxy_next_upstream on;
        proxy_next_upstream_tries 2;
    }
}

EOF

$t->run_daemon(\&stream_daemon);
$t->run()->waitforsocket('127.0.0.1:8089');

###############################################################################

is(stream_get('.', '127.0.0.1:8081'), '', 'next upstream off');
is(stream_get('.', '127.0.0.1:8082'), 'SEE-THIS', 'next upstream on');

# make sure backup is not tried

is(stream_get('.', '127.0.0.1:8083'), '', 'next upstream tries');

###############################################################################

sub stream_get {
	my ($data, $peer) = @_;

	my $s = stream_connect($peer);
	stream_write($s, $data);
	my $r = stream_read($s);

	$s->close;
	return $r;
}

sub stream_connect {
	my $peer = shift;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => $peer
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
	if (IO::Select->new($s)->can_read(5)) {
		$s->sysread($buf, 1024);
	};

	log_in($buf);
	return $buf;
}

###############################################################################

sub stream_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:8089',
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

		$buffer = 'SEE-THIS';

		log2o("$client $buffer");

		$client->syswrite($buffer);

	} continue {
		close $client;
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
