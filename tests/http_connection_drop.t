#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for HTTP "proxy_connection_drop" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()
	->has(qw/http http_api proxy upstream_zone/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:5858 valid=1s ipv6=off;
    resolver_timeout 10s;

    upstream u {
        zone z 1m;
        server test.example.com:%%PORT_8081%% resolve;
    }

    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location /on {
            proxy_connection_drop on;
            proxy_pass http://u;
        }

        location /off {
            proxy_connection_drop off;
            proxy_pass http://u;
        }

        location /api/ {
            api /;
        }
    }
}

EOF

# TODO: use substituted ports for parallel execution for DNS server
my $addrs = {'test.example.com' => ['127.0.0.1']};
$t->start_resolver(5858, $addrs);

$t->run_daemon(\&http_daemon, port(8081), $t);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->run()->plan(2);

###############################################################################

like(http_get('/on'), qr/502/, 'Connection drop on');

$t->restart_resolver(5858, $addrs);

wait_peer('127.0.0.1') or diag("$0: Peer is not ready");

like(http_get('/off'), qr/200/, 'Connection drop off');

$t->stop_resolver();

###############################################################################

sub http_daemon {
	my ($port, $t) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/on' or $uri eq '/off') {
			$t->restart_resolver(5858, {'test.example.com' => ['127.0.0.2']});
			wait_peer('127.0.0.2') or diag("$0: Peer is not ready");
		}

		print $client <<EOF;
HTTP/1.1 200 OK
Connection: close

EOF

		close $client;
	}
}

sub wait_peer {
	my ($peer) = @_;
	$peer .= ':' . port(8081);

	my $ok = 0;
	for (1 .. 50) {
		my $j = get_json('/api/status/http/upstreams/u/');
		if (exists $j->{peers}{$peer}) {
			$ok = 1;
			last;
		}
		select undef, undef, undef, 0.5;
	}
	return $ok;
}

###############################################################################
