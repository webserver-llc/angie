#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for stream proxy module with datagrams.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ dgram /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream udp/)->plan(5)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    proxy_timeout        1s;

    server {
        listen           127.0.0.1:%%PORT_8080_UDP%% udp;
        proxy_pass       127.0.0.1:%%PORT_8081_UDP%%;

        proxy_responses  0;
    }

    server {
        listen           127.0.0.1:%%PORT_8082_UDP%% udp;
        proxy_pass       127.0.0.1:%%PORT_8081_UDP%%;

        proxy_responses  2;
    }

    server {
        listen           127.0.0.1:%%PORT_8083_UDP%% udp;
        proxy_pass       127.0.0.1:%%PORT_8081_UDP%%;
    }
}

EOF


$t->run_daemon(\&udp_daemon, port(8081), $t);
$t->run();
$t->waitforfile($t->testdir . '/' . port(8081));

###############################################################################

my $s = dgram('127.0.0.1:' . port(8080));
is($s->io('1', read => 1, read_timeout => 0.5), '', 'proxy responses 0');

$s = dgram('127.0.0.1:' . port(8082));
is($s->io('1'), '1', 'proxy responses 1');
is($s->io('2', read => 2), '12', 'proxy responses 2');
is($s->io('3', read => 3, read_timeout => 0.5), '12', 'proxy responses 3');

$s = dgram('127.0.0.1:' . port(8083));
is($s->io('3', read => 3), '123', 'proxy responses default');

###############################################################################

sub udp_daemon {
	my ($port, $t) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'udp',
		LocalAddr => '127.0.0.1:' . port(8081),
		Reuse => 1,
	)
		or die "Can't create listening socket: $!\n";

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . port(8081);
	close $fh;

	while (1) {
		$server->recv(my $buffer, 65536);
		$server->send($_) for (1 .. $buffer);
	}
}

###############################################################################
