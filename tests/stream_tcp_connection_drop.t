#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for TCP stream "proxy_connection_drop" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;
use Test::Nginx::Stream qw/stream/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()
	->has(qw/http stream proxy upstream_zone/)
	->has_daemon("dnsmasq")->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;

        location /api/ {
            api /;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    resolver 127.0.0.1:5959 valid=1s ipv6=off;
    resolver_timeout 10s;

    upstream u {
        zone z 1m;
        server test.example.com:%%PORT_8083%% resolve;
    }

    server {
        listen 127.0.0.1:%%PORT_8081%%;
        proxy_connection_drop on;
        proxy_pass u;
    }

    server {
        listen 127.0.0.1:%%PORT_8082%%;
        proxy_connection_drop off;
        proxy_pass u;
    }

}

EOF

$t->write_file_expand('dnsmasq1.conf', <<'EOF');
port=5959
listen-address=127.0.0.1
no-dhcp-interface=
no-hosts
no-resolv
addn-hosts=%%TESTDIR%%/host1.txt

EOF

$t->write_file_expand('dnsmasq2.conf', <<'EOF');
port=5959
listen-address=127.0.0.1
no-dhcp-interface=
no-hosts
no-resolv
addn-hosts=%%TESTDIR%%/host2.txt

EOF

$t->write_file_expand('host1.txt', <<'EOF');
127.0.0.1  test.example.com
EOF

$t->write_file_expand('host2.txt', <<'EOF');
127.0.0.2  test.example.com
EOF

$t->run_dnsmasq('dnsmasq1.conf');
$t->run_daemon(\&stream_daemon, port(8083), $t);

$t->run();

$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

is(stream_send(port(8081), 'ping'), '', 'Connection drop on');

$t->restart_dnsmasq('dnsmasq1.conf');

wait_peer('127.0.0.1');

is(stream_send(port(8082), 'ping'), 'pong', 'Connection drop off');

$t->stop_dnsmasq();

###############################################################################

sub stream_send {
	my ($port, $str) = @_;

	my $s = stream('127.0.0.1:' . $port);
	return $s->io($str);
}

sub stream_daemon {
	my ($port, $t) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		$client->sysread(my $buffer, 1024) or next;

		$t->restart_dnsmasq('dnsmasq2.conf');

		wait_peer('127.0.0.2');

		$client->syswrite('pong');

		close $client;
	}
}

sub wait_peer {
	my ($peer) = @_;
	$peer .= ':' . port(8083);

	for (1 .. 50) {
		my $j = get_json('/api/status/stream/upstreams/u/');
		last if exists $j->{peers}{$peer};
		select undef, undef, undef, 0.5;
	}
}

###############################################################################
