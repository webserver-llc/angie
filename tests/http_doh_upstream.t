#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for the doh (DNS-over-HTTPS) module — transport, retry,
# keepalive, and API stats.

###############################################################################

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_LINGER);
use Test::Deep qw(cmp_deeply superhashof);
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::DoH qw(
	dns_query dns_response dns_nxdomain_response dns_tc_response
	:io :daemon :http
);
use Test::Utils qw/ get_json /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http doh http_api upstream_zone upstream_keepalive/)->plan(13);

my ($tc_fb_tcp_sock, $tc_fb_udp_sock) = port(8091, dual => 1);
my ($ka_auto_tcp_sock, $ka_auto_udp_sock) = port(8092, dual => 1);
my ($ka_nu_tcp_sock, $ka_nu_udp_sock) = port(8093, dual => 1);

my $cfg = <<'ENDCFG';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream tcp_retry_upstream {
        server 127.0.0.1:8090;
        server 127.0.0.1:8081;
    }

    upstream reset_retry_upstream {
        server 127.0.0.1:8083;
        server 127.0.0.1:8081;
    }

    upstream slow_retry_upstream {
        server 127.0.0.1:8082;
        server 127.0.0.1:8090;
    }

    upstream tc_fb_upstream {
        zone tc_fb_zone 1m;
        server 127.0.0.1:8091;
    }

    upstream tc_fb_2srv_upstream {
        zone tc_fb_2srv_zone 1m;
        server 127.0.0.1:8091;
        server 127.0.0.1:8081;
    }

    upstream ka_tcp_upstream {
        zone ka_tcp_zone 1m;
        server 127.0.0.1:8084;
        keepalive 4;
    }

    upstream ka_auto_upstream {
        zone ka_auto_zone 1m;
        server 127.0.0.1:8092;
        keepalive 4;
    }

    upstream ka_nu_upstream {
        zone ka_nu_zone 1m;
        server 127.0.0.1:8093;
        server 127.0.0.1:8093;
        keepalive 4;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /dns-query-timeout {
            doh_pass 127.0.0.1:8082;
            doh_transport tcp;
            doh_read_timeout 5s;
        }

        location /dns-query-udp-fallback {
            doh_pass 127.0.0.1:8091;
            add_header X-Upstream-Transport $upstream_transport;
            add_header X-Upstream-Status $upstream_status;
        }

        location /dns-query-tc-fb-upstream {
            doh_pass tc_fb_upstream;
            doh_next_upstream_tries 1;
            add_header X-Upstream-Addr $upstream_addr;
            add_header X-Upstream-Transport $upstream_transport;
        }

        location /dns-query-tc-fb-2srv {
            doh_pass tc_fb_2srv_upstream;
            add_header X-Upstream-Addr $upstream_addr;
        }

        location /dns-query-udp-no-fallback {
            doh_pass 127.0.0.1:%%PORT_9081_UDP%%;
            doh_transport udp;
        }

        location /dns-query-retry {
            doh_pass 127.0.0.1:8085;
            doh_transport tcp;
            doh_next_upstream error timeout invalid_response;
            doh_next_upstream_tries 2;
        }

        location /dns-query-invalid {
            doh_pass 127.0.0.1:8086;
            doh_transport tcp;
            doh_next_upstream invalid_response;
            doh_next_upstream_tries 1;
        }

        location /dns-query-upstream-retry {
            doh_pass tcp_retry_upstream;
            doh_transport tcp;
        }

        location /dns-query-partial {
            doh_pass 127.0.0.1:8087;
            doh_transport tcp;
        }

        location /dns-query-oversized {
            doh_pass 127.0.0.1:8088;
            doh_transport tcp;
        }

        location /dns-query-drop-partial {
            doh_pass 127.0.0.1:8089;
            doh_transport tcp;
        }

        location /dns-query-reset-retry {
            doh_pass reset_retry_upstream;
            doh_transport tcp;
        }

        location /dns-query-next-timeout {
            doh_pass slow_retry_upstream;
            doh_transport tcp;
            doh_read_timeout 200ms;
            doh_connect_timeout 100ms;
            doh_next_upstream error timeout;
            doh_next_upstream_tries 10;
            doh_next_upstream_timeout 500ms;
        }

        location /dns-query-ka-tcp {
            doh_pass ka_tcp_upstream;
            doh_transport tcp;
        }

        location /dns-query-ka-auto {
            doh_pass ka_auto_upstream;
            add_header X-Upstream-Transport $upstream_transport;
        }

        location /dns-query-ka-nu {
            doh_pass ka_nu_upstream;
            doh_next_upstream error timeout;
            add_header X-Upstream-Transport $upstream_transport;
        }

        location /dns-query-ka-nu-tcp {
            doh_pass ka_nu_upstream;
            doh_transport tcp;
        }

        location /api/ {
            api /;
        }
    }
}

ENDCFG

$t->write_file_expand('nginx.conf', $cfg);

# Normal TCP
$t->run_daemon(\&tcp_dns_daemon, $t, port(8081),
	sub { dns_response($_[0], '127.0.0.1', 300) });

# Blackhole
$t->run_daemon(\&dns_blackhole_daemon, $t, port(8082));

# Reset daemon — reads query then RSTs
$t->run_daemon(\&dns_reset_daemon, $t, port(8083));

# UDP TC-only daemon
$t->run_daemon(\&udp_dns_daemon, $t, port(9081, udp => 1),
	sub { dns_tc_response($_[0]) });

# Retry daemon — first connection fails, second succeeds
$t->run_daemon(\&dns_retry_daemon, $t, port(8085));

# Invalid daemon — cycles through malformed responses
my $invalid_idx = 0;
$t->run_daemon(\&tcp_dns_daemon, $t, port(8086),
	sub {
		my ($query_data) = @_;

		my $idx = $invalid_idx++ % 4;
		if ($idx == 0) {
			my $r = dns_response($query_data, '127.0.0.1', 300);
			substr($r, 0, 2) = pack('n', 0xFFFF);
			return $r;
		} elsif ($idx == 1) {
			my $r = dns_response($query_data, '127.0.0.1', 300);
			substr($r, 2, 2) = pack('n', 0x0100);
			return $r;
		} elsif ($idx == 2) {
			return pack('nn', unpack('n', $query_data), 0x8180);
		} else {
			return pack('nn', unpack('n', $query_data), 0x8180) . "\x00" x 3;
		}
	}
);

# Partial response daemon
$t->run_daemon(\&dns_partial_daemon, $t, port(8087));

# Oversized response daemon
$t->run_daemon(\&dns_oversized_daemon, $t, port(8088));

# Drop-partial daemon — sends 1 byte then closes
$t->run_daemon(\&dns_drop_partial_daemon, $t, port(8089));

# TC fallback dual daemon
$t->run_daemon(\&dual_dns_daemon, $t,
	$tc_fb_tcp_sock, $tc_fb_udp_sock,
	sub { dns_response($_[0], '127.0.0.1', 300) },
	sub { dns_tc_response($_[0]) });

# Keepalive TCP daemon (persistent)
$t->run_daemon(\&tcp_dns_daemon, $t, port(8084),
	sub { dns_response($_[0], '127.0.0.1', 300) },
	persistent => 1);

# Keepalive auto dual daemon (persistent TCP)
$t->run_daemon(\&dual_dns_daemon, $t,
	$ka_auto_tcp_sock, $ka_auto_udp_sock,
	sub { dns_response($_[0], '127.0.0.1', 300) },
	sub { dns_response($_[0], '127.0.0.1', 300) },
	persistent => 1);

# Keepalive next-upstream dual daemon
$t->run_daemon(\&dns_ka_nu_daemon, $t, $ka_nu_tcp_sock, $ka_nu_udp_sock);

$t->run();

$t->waitforsocket('127.0.0.1:' . port(8080 + $_)) for (1 .. 9);
for (1 .. 3) {
	$t->waitforsocket('127.0.0.1:' . port(8090 + $_));
	$t->waitforsocket('127.0.0.1:' . port(8090 + $_), 'udp');
}
$t->waitforsocket('127.0.0.1:' . port(9081), 'udp');

###############################################################################

my $query = dns_query('example.com', 1);

subtest 'TC fallback: UDP->TCP' => sub {
	# POST
	my $resp = doh_post('/dns-query-udp-fallback', $query);
	like($resp, qr/HTTP\/1\.. 200/,
		'UDP POST TC=1 fallback to TCP - status 200');
	like($resp, qr/X-Upstream-Transport:\s*UDP, TCP\b/,
		'$upstream_transport shows UDP then TCP after POST TC fallback');
	like($resp, qr/X-Upstream-Status:\s*426, 200/,
		'$upstream_status shows 426 then 200 after POST TC fallback');

	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'UPD POST TC fallback response query ID matches');

	my $tc = doh_tc_flag($body);
	is($tc, 0, 'UPD POST TC fallback response has TC=0');

	# GET
	$resp = doh_get('/dns-query-udp-fallback', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'UDP GET TC fallback - 200');
	like($resp, qr/X-Upstream-Transport:\s*UDP, TCP\b/,
		'$upstream_transport shows UDP then TCP after GET TC fallback');
	like($resp, qr/X-Upstream-Status:\s*426, 200/,
		'$upstream_status shows 426 then 200 after GET TC fallback');

	$body = doh_extract_body($resp);
	$tc = doh_tc_flag($body);
	is($tc, 0, 'UDP GET TC fallback response TC=0');

	my $ancount = doh_ancount($body);
	ok($ancount > 0, 'UDP GET TC fallback has answers');
};

# TC fallback: UDP-only (no fallback) -> 500
like(doh_post('/dns-query-udp-no-fallback', $query), qr/HTTP\/1\.. 500/,
	'UDP TC=1 no fallback - status 500');

subtest 'TC fallback' => sub {
	my $ok = 1;
	for (1 .. 5) {
		my $resp = doh_post('/dns-query-tc-fb-upstream', $query);
		if ($resp !~ /HTTP\/1\.. 200/) {
			$ok = 0;
			last;
		}
	}
	ok($ok, 'TC fallback upstream group - 5 sequential requests all 200');

	my $resp = doh_post('/dns-query-tc-fb-upstream', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TC fallback upstream - 200');

	my $peers = get_json('/api/status/http/upstreams/tc_fb_upstream/peers/');
	my $server = '127.0.0.1:' . port(8091);
	cmp_deeply($peers, {$server => superhashof({})}, 'only one peer in stat');

	my $peer = $peers->{$server};
	is($peer->{health}{fails}, 0,
		"peer fails=0 (no passive health penalty)");
	cmp_deeply($peer->{responses}, {200 => 6, 426 => 6},
		"peer responses: no 502 after TC fallback, 426 an 200 recorded");

	like($resp, qr/X-Upstream-Addr:\s*127\.0\.0\.1:(\d+), 127\.0\.0\.1:\1/,
		'TC fallback reconnects to the same server');
	like($resp, qr/X-Upstream-Transport:\s*UDP, TCP\b/,
		'$upstream_transport shows UDP then TCP after TC fallback');
};

# TC fallback: 2-server upstream, fails=0 on TC server
subtest '2-srv TC fallback: fails=0 on TC server' => sub {
	# First send a request to populate stats
	doh_post('/dns-query-tc-fb-2srv', $query);

	my $j = get_json('/api/status/http/upstreams/tc_fb_2srv_upstream/peers/');

	my $tc_server = $j->{'127.0.0.1:' . port(8091)};
	ok(defined $tc_server, 'found TC server in API')
		or return;

	is($tc_server->{health}{fails}, 0, "TC server fails=0");
	is($tc_server->{responses}{502}, undef,
		"TC server: no 502 in peer stats after TC fallback");
	is($tc_server->{responses}{426}, 1,
		"TC server: 426 recorded in peer stats after TC fallback");
};

subtest 'Invalid DNS responses -> 502' => sub {
	like(doh_post('/dns-query-invalid', $query), qr/HTTP\/1\.. 502/,
		'Wrong query ID - 502');
	like(doh_post('/dns-query-invalid', $query), qr/HTTP\/1\.. 502/,
		'QR=0 response - 502');
	like(doh_post('/dns-query-invalid', $query), qr/HTTP\/1\.. 502/,
		'Too-short DNS response - 502');
	like(doh_post('/dns-query-invalid', $query), qr/HTTP\/1\.. 502/,
		'Invalid TCP length - 502');
};

subtest 'upstream retry' => sub {
	like(doh_post('/dns-query-retry', $query), qr/HTTP\/1\.. 200/,
		'Upstream retry after error - 200');

	like(doh_post('/dns-query-reset-retry', $query), qr/HTTP\/1\.. 200/,
		'Upstream retry after reset - 200');

	like(doh_post('/dns-query-upstream-retry', $query), qr/HTTP\/1\.. 200/,
		'Upstream retry after connection failure - 200');
};

like(doh_post('/dns-query-partial', $query), qr/HTTP\/1\.. 200/,
	'TCP partial response - 200');

like(doh_post('/dns-query-oversized', $query), qr/HTTP\/1\.. 200/,
	'TCP oversized response - 200');

like(doh_post('/dns-query-drop-partial', $query), qr/HTTP\/1\.. 502/,
	'Upstream drops after 1 byte - 502');

like(doh_post('/dns-query-next-timeout', $query), qr/HTTP\/1\.. (502|504)/,
	'Next upstream timeout - retries capped by time');

subtest 'TCP keepalive' => sub {
	my $resp = doh_post('/dns-query-ka-tcp', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TCP keepalive: first request - 200');

	$resp = doh_post('/dns-query-ka-tcp', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TCP keepalive: second request - 200');

	my $j = get_json('/api/status/http/upstreams/ka_tcp_upstream/');

	ok(defined $j->{keepalive}, 'keepalive stat present in upstream API');
	is($j->{keepalive}, 1,
		'keepalive cache has 1 connection (cached after last request)');

	cmp_deeply(
		$j->{peers},
		{'127.0.0.1:' . port(8084) => superhashof({responses => {200 => 2}})},
		"peer 127.0.0.1:" . port(8084) . ": 2 successful responses"
	);
};

subtest 'Auto+keepalive' => sub {
	my $resp = doh_post('/dns-query-ka-auto', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Auto+keepalive: first request - 200');
	like($resp, qr/X-Upstream-Transport:\s*UDP\b/,
		'$upstream_transport is UDP (first request, no cache)');

	$resp = doh_post('/dns-query-ka-auto', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Auto+keepalive: second request - 200');
	like($resp, qr/X-Upstream-Transport:\s*UDP\b/,
		'$upstream_transport is UDP (second request, still no TCP cache)');

	$resp = doh_post('/dns-query-ka-auto', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Auto+keepalive: third request - 200');
	like($resp, qr/X-Upstream-Transport:\s*UDP\b/,
		'$upstream_transport is UDP (third request, still no TCP cache)');

	my $j = get_json('/api/status/http/upstreams/ka_auto_upstream/');

	ok(defined $j->{keepalive}, 'keepalive stat present in upstream API');

	cmp_deeply(
		$j->{peers},
		{'127.0.0.1:' . port(8092) => superhashof({responses => {200 => 3}})},
		"peer 127.0.0.1:" . port(8092) . ": 3 successful responses"
	);
};

subtest 'Cached TCP fail + next-upstream reset' => sub {
	# Populate keepalive cache with TCP connection
	my $resp = doh_post('/dns-query-ka-nu-tcp', $query);
	like($resp, qr/HTTP\/1\.. 200/,
		'Cached TCP fail: first TCP request - 200');

	# Auto-mode request: cached TCP connection gets RST, next-upstream to UDP
	$resp = doh_post('/dns-query-ka-nu', $query);
	like($resp, qr/HTTP\/1\.. 200/,
		'Cached TCP fail: next-upstream resets transport - 200');
	like($resp, qr/X-Upstream-Transport:\s*TCP, UDP\b/,
		'$upstream_transport shows TCP then UDP after cached-TCP RST');

	# Verify subsequent requests work
	$resp = doh_post('/dns-query-ka-nu', $query);
	like($resp, qr/HTTP\/1\.. 200/,
		'Cached TCP fail: subsequent request - 200');
};

###############################################################################
# Specialized daemons

sub dns_reset_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS reset server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		my $query_data = read_tcp_query($client);
		$client->setsockopt(SOL_SOCKET, SO_LINGER, pack('ll', 1, 0));
		$client->close;
	}
}

sub dns_retry_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS retry server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my $fail_count = 0;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		if ($fail_count < 1) {
			$fail_count++;
			$client->close;
			next;
		}

		my $query_data = read_tcp_query($client);
		if (defined $query_data) {
			my $response_data = dns_response($query_data, '127.0.0.1', 300);
			send_tcp_response($client, $response_data);
		}

		$client->close;
		$fail_count = 0;
	}
}

sub dns_partial_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
		NoDelay  => 1,
	) or die "Can't create DNS partial server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $buf = read_tcp_query($client);
		next unless defined $buf;

		my $response = dns_response($buf, '127.0.0.1', 300);
		my $response_len = pack('n', length($response));

		my $half = int(length($response) / 2);
		$half = 1 if $half == 0;

		$client->write($response_len . substr($response, 0, $half));
		select undef, undef, undef, 5;
		$client->write(substr($response, $half));

		$client->close;
	}
}

sub dns_oversized_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS oversized server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $buf = read_tcp_query($client);
		next unless defined $buf;

		my $response = dns_response($buf, '127.0.0.1', 300);
		my $short_len = length($response) - 4;
		my $response_len = pack('n', $short_len);

		$client->write($response_len . $response);
		$client->close;
	}
}

sub dns_drop_partial_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS drop-partial server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $query_data = read_tcp_query($client);
		$client->write("\x00");
		$client->close;
	}
}

sub dns_ka_nu_daemon {
	my ($t, $tcp_server, $udp_server) = @_;

	local $SIG{PIPE} = 'IGNORE';

	my $sel = IO::Select->new($tcp_server, $udp_server);

	while (1) {
		my @ready = $sel->can_read(5);
		for my $sock (@ready) {
			if ($sock == $udp_server) {
				my $client_addr = $udp_server->recv(my $query_data, 65535);
				next unless defined $client_addr;
				next if length($query_data) < 12;

				my $response_data = dns_response($query_data, '127.0.0.1', 300);
				$udp_server->send($response_data, 0, $client_addr);

			} elsif ($sock == $tcp_server) {
				my $client = $tcp_server->accept();
				next unless $client;
				$client->autoflush(1);

				my $req_count = 0;

				while (1) {
					my $query_data = read_tcp_query($client);
					last if !defined $query_data;

					$req_count++;

					if ($req_count <= 1) {
						my $response_data = dns_response($query_data,
							'127.0.0.1', 300);
						send_tcp_response($client, $response_data);
					} else {
						$client->setsockopt(SOL_SOCKET, SO_LINGER,
							pack('ll', 1, 0));
						$client->close;
						last;
					}
				}

				$client->close if $req_count <= 1;
			}
		}
	}
}
