#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for stream upstream sticky module with drain

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Utils qw/get_json :re/;
use Test::Control qw/stop_pid/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/stream stream_ssl stream_ssl_preread stream_upstream_zone/)
	->has(qw/stream_upstream_sticky http http_api http_ssl socket_ssl/)
	->plan(24)
	->has_daemon('openssl')
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format  status  "$status $upstream_addr $upstream_sticky_status";

    map $ssl_preread_server_name $route {
        b1.example.com           b1;
        b2.example.com           b2;
        b3.example.com           b3;
        b4.example.com           unknown;
        default                  "";
    }

    upstream u_route {
        server 127.0.0.1:8081 sid=b1 max_fails=1 fail_timeout=1s drain;
        server 127.0.0.1:8082 sid=b2;
        server 127.0.0.1:8083 sid=b3;
        zone z 1m;

        sticky route $route;
        sticky_strict on;
    }

    server {
        listen      127.0.0.1:8090;
        ssl_preread on;
        proxy_pass  u_route;

        access_log  %%TESTDIR%%/stream-access.log status;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen 127.0.0.1:8080;

        proxy_ssl_session_reuse off;
        proxy_ssl_server_name on;

        location /status/ {
            api /status/stream/;
        }

        location /any {
            proxy_ssl_name "something";
            proxy_pass https://127.0.0.1:8090;
        }

        location /b1_route {
            proxy_ssl_name b1.example.com;
            proxy_pass https://127.0.0.1:8090;
        }

        location /b2_route {
            proxy_ssl_name b2.example.com;
            proxy_pass https://127.0.0.1:8090;
        }

        location /b3_route {
            proxy_ssl_name b3.example.com;
            proxy_pass https://127.0.0.1:8090;
        }
    }
}

EOF

$t->prepare_ssl();

my ($port1, $port2, $port3) = (port(8081), port(8082), port(8083));

my $d = $t->testdir();

my $b1_pid = $t->run_daemon(\&http_daemon_ssl, $port1);
$t->run_daemon(\&http_daemon_ssl, $port2);
$t->run_daemon(\&http_daemon_ssl, $port3);

$t->run();

$t->waitforsslsocket('127.0.0.1:' . $port1);
$t->waitforsslsocket('127.0.0.1:' . $port2);
$t->waitforsslsocket('127.0.0.1:' . $port3);

###############################################################################

# expect RR for requests without known route and no draining server
like(http_get('/any'), "/X-Port: $port2/", 'b2 initial RR');
like(http_get('/any'), "/X-Port: $port3/", 'b3 RR switch 1');
like(http_get('/any'), "/X-Port: $port2/", 'b2 RR switch 2');
like(http_get('/any'), "/X-Port: $port3/", 'b3 RR switch 3');

# expect sticky for requests with known route
like(http_get('/b1_route'), "/X-Port: $port1/",
	'initial b1 request to draining');
like(http_get('/b1_route'), "/X-Port: $port1/",
	'expected sticky b1 request to draining');
like(http_get('/b2_route'), "/X-Port: $port2/", 'initial b2 request');
like(http_get('/b2_route'), "/X-Port: $port2/", 'expected sticky b2');
like(http_get('/b3_route'), "/X-Port: $port3/", 'initial b3 request');
like(http_get('/b3_route'), "/X-Port: $port3/", 'expected sticky b3');

###############################################################################

# check that API returns SID values for peers correctly and state is correct

my $j = get_json("/status/upstreams/u_route/peers/127.0.0.1:$port1");
is($j->{sid}, 'b1', 'b1 has proper sid');
is($j->{state}, 'draining', 'b1 is draining');

cmp_deeply(
	$j->{health},
	{
		unavailable => 0, downtime => 0, fails => 0,
	},
	'b1 health is OK'
);

$j = get_json("/status/upstreams/u_route/peers/127.0.0.1:$port2");
is($j->{sid}, 'b2', 'b2 has proper sid');
is($j->{state}, 'up', 'b2 is up');

# fail the peer
stop_pid($b1_pid, 1);

like(http_get('/b1_route'), '/502/', 'b1 is dead');
like(http_get('/b2_route'), "/X-Port: $port2/", 'b2 is alive');

# wait a bit to increase downtime
select undef, undef, undef, 0.5;

$j = get_json("/status/upstreams/u_route/peers/127.0.0.1:$port1");

is($j->{state}, 'draining', 'b1 is draining');
cmp_deeply(
	$j->{health},
	{
		unavailable => 1, downtime => $NUM_RE, fails => 1,
		downstart => $TIME_RE
	},
	'b1 health (peer is dead)'
);
ok($j->{health}{downtime} > 0, 'b1 nonzero downtime');

# revive the peer
$t->run_daemon(\&http_daemon_ssl, $port1);
$t->waitforsslsocket('127.0.0.1:' . $port1);

# wait for fail_timeout and a bit more
select undef, undef, undef, 2;

like(http_get('/b1_route'), "/X-Port: $port1/", 'b1 is alive');

$j = get_json("/status/upstreams/u_route/peers/127.0.0.1:$port1");

is($j->{state}, 'draining', 'b1 is draining');
cmp_deeply(
	$j->{health},
	{
		unavailable => 1, downtime => $NUM_RE, fails => 1,
	},
	'b1 health (peer is revived, no downstart)'
);

# check that downtime stopped growing
my $downtime = $j->{health}{downtime};

# wait a bit
select undef, undef, undef, 2;

$j = get_json("/status/upstreams/u_route/peers/127.0.0.1:$port1/health/");
is($j->{downtime}, $downtime, 'b1 downtime stopped growing');

###############################################################################

sub http_daemon_ssl {
	my ($port) = @_;

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

		IO::Socket::SSL->start_SSL(
			$client,
			SSL_server => 1,
			SSL_cert_file => "$d/localhost.crt",
			SSL_key_file => "$d/localhost.key",
		);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my $uri = '';
		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		Test::Nginx::log_core('||', "$port: response, 200");
		print $client <<EOF;
HTTP/1.1 200 OK
Connection: close
X-Port: $port

OK
EOF

		close $client;
	}
}

