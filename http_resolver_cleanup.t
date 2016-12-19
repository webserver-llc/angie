#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http resolver, worker process termination.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(1);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            resolver 127.0.0.1:%%PORT_8081_UDP%%;
            proxy_pass http://example.net/$args;
        }

        location /pid {
            add_header X-Pid $pid always;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t);
$t->run()->waitforfile($t->testdir . '/' . port(8081));

###############################################################################

my ($s);

TODO: {
todo_skip 'use-after-free', 1 unless $ENV{TEST_NGINX_UNSAFE}
	or $t->has_version('1.11.8');

# truncated UDP response, no response over TCP

$s = http_get('/', start => 1);

pass('request');

sleep 1;

}

# use-after-free in worker on fast shutdown

http_get('/pid') =~ qr/X-Pid: (\d+)/;
kill 'TERM', $1;

###############################################################################

sub dns_daemon {
	my ($t) = @_;
	my ($data);

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => port(8081),
		Proto => 'udp',
	)
		or die "Can't create UDP socket: $!\n";

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . port(8081);
	close $fh;

	while (1) {
		$socket->recv($data, 65536);
		# truncation bit set
		$data |= pack("n2", 0, 0x8380);
		$socket->send($data);
	}
}

###############################################################################
