#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for the doh (DNS-over-HTTPS) module — basic functionality.

###############################################################################

use warnings;
use strict;

use MIME::Base64 qw/encode_base64url/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ http_start :DEFAULT /;
use Test::Nginx::DoH qw(
	dns_query dns_response dns_nxdomain_response :io :daemon :http
);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http doh/)->plan(29);

my $cfg = <<'ENDCFG';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /dns-query {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
        }

        location /dns-query-timeout {
            doh_pass 127.0.0.1:8082;
            doh_transport tcp;
            doh_read_timeout 5s;
        }

        location /dns-query-refused {
            doh_pass 127.0.0.1:8084;
            doh_transport tcp;
        }

        location /dns-query-small {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            doh_max_size 16;
        }

        location /dns-query-nxdomain {
            doh_pass 127.0.0.1:8083;
            doh_transport tcp;
        }

        location /dns-query-udp {
            doh_pass 127.0.0.1:%%PORT_9081_UDP%%;
            doh_transport udp;
        }

        location /dns-query-udp-short {
            doh_pass 127.0.0.1:%%PORT_9082_UDP%%;
            doh_transport udp;
        }

        location /dns-query-udp-large {
            doh_pass 127.0.0.1:%%PORT_9083_UDP%%;
            doh_transport udp;
            doh_max_size 32;
        }

        location /dns-query-max-size-decoded {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            doh_max_size 36;
        }

        location /dns-query-no-retry {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            doh_next_upstream off;
        }

        location /dns-query-keepalive {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            doh_socket_keepalive on;
        }

        location /dns-query-connect-timeout {
            doh_pass 127.0.0.1:8088;
            doh_transport tcp;
            doh_connect_timeout 100ms;
        }

        location /dns-query-send-timeout {
            doh_pass 127.0.0.1:8082;
            doh_transport tcp;
            doh_send_timeout 100ms;
            doh_read_timeout 100ms;
        }

        location /dns-query-small-buf {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            client_body_buffer_size 8;
        }

        location /dns-query-in-file-only {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            client_body_in_file_only on;
        }
    }
}

ENDCFG

$t->write_file_expand('nginx.conf', $cfg);

# Normal TCP daemon — TTL=300
$t->run_daemon(\&tcp_dns_daemon, $t, port(8081),
	sub { dns_response($_[0], '127.0.0.1', 300) });

# Normal UDP daemon — TTL=300
$t->run_daemon(\&udp_dns_daemon, $t, port(9081, udp => 1),
	sub { dns_response($_[0], '127.0.0.1', 300) });

# Blackhole daemon (never responds)
$t->run_daemon(\&dns_blackhole_daemon, $t, port(8082));

# NXDOMAIN daemon
$t->run_daemon(\&tcp_dns_daemon, $t, port(8083),
	sub { dns_nxdomain_response($_[0]) });

# UDP short daemon — sends < 12 bytes
$t->run_daemon(\&udp_dns_daemon, $t, port(9082, udp => 1),
	sub { pack('nn', unpack('n', $_[0]), 0x8180) });

# UDP large daemon — sends response larger than max_size
$t->run_daemon(\&udp_dns_daemon, $t, port(9083, udp => 1),
	sub {
		my $id = unpack('n', $_[0]);
		my $response = pack('nnnnnn', $id, 0x8180, 0, 1, 0, 0)
			. pack('n', 0xc00c) . pack('nn', 1, 1)
			. pack('N', 300) . pack('n', 64) . ("\x00" x 64);
		return $response;
	}
);

$t->run();

for (1 .. 3) {
	$t->waitforsocket('127.0.0.1:' . port(8080 + $_));
	$t->waitforsocket('127.0.0.1:' . port(9080 + $_), 'udp');
}

###############################################################################

my $query = dns_query('example.com', 1);

subtest 'POST basic query' => sub {
	my $resp = doh_post('/dns-query', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'POST valid query - status 200');
	like($resp, qr/Content-Type: application\/dns-message/i,
		'POST valid query - content type');
	like($resp, qr/Cache-Control: max-age=300/i,
		'Cache-Control matches DNS TTL');
};

subtest 'GET basic query' => sub {
	my $resp = doh_get('/dns-query', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'GET valid query - status 200');

	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'GET response query ID matches');
};

subtest 'Disallowed methods -> 405' => sub {
	like(http("PUT /dns-query HTTP/1.0\r\nHost: localhost\r\n"
		. "Content-Length: 0\r\n\r\n"),
		qr/HTTP\/1\.. 405/, 'PUT method not allowed');
	like(http("HEAD /dns-query HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		qr/HTTP\/1\.. 405/, 'HEAD method not allowed');
};

like(http(POST_req('/dns-query', $query)), qr/HTTP\/1\.. 415/,
	'Wrong content type - 415');

like(http_get('/dns-query?dns=!!!invalid!!!'), qr/HTTP\/1\.. 400/,
	'Invalid base64url - 400');

like(http_get('/dns-query'), qr/HTTP\/1\.. 400/,
	'GET missing dns param - 400');

like(http_get('/dns-query?dns='), qr/HTTP\/1\.. 400/,
	'GET empty dns param - 400');

{
	my $short_query = pack('nn', 0x1234, 0x0100);
	like(doh_get("/dns-query", $short_query), qr/HTTP\/1\.. 400/,
		'GET short DNS query (< 12 bytes) - 400');
}

like(http("POST /dns-query HTTP/1.0\r\n"
	. "Host: localhost\r\n"
	. "Content-Type: application/dns-message\r\n"
	. "Content-Length: 0\r\n\r\n"),
	qr/HTTP\/1\.. 400/, 'POST empty body - 400');

subtest 'POST chunked body' => sub {
	# chunked valid query -> 200
	my $cl = sprintf("%x", length $query);
	like(http("POST /dns-query HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Content-Type: application/dns-message\r\n"
		. "Connection: close\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n"
		. $cl . "\r\n" . $query . "\r\n"
		. "0\r\n\r\n"),
		qr/HTTP\/1\.. 200/, 'POST chunked valid query - 200');

	# chunked body > max_size -> 413
	like(http("POST /dns-query-small HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Content-Type: application/dns-message\r\n"
		. "Connection: close\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n"
		. $cl . "\r\n" . $query . "\r\n"
		. "0\r\n\r\n"),
		qr/HTTP\/1\.. 413/, 'POST chunked body too large - 413');

	# chunked short body -> 400
	my $short = pack('nn', 0x1234, 0x0100);
	my $scl = sprintf("%x", length $short);
	like(http("POST /dns-query HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Content-Type: application/dns-message\r\n"
		. "Connection: close\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n"
		. $scl . "\r\n" . $short . "\r\n"
		. "0\r\n\r\n"),
		qr/HTTP\/1\.. 400/, 'POST chunked short body - 400');
};

subtest 'max_size' => sub {
	# POST body > max_size -> 413
	like(doh_post('/dns-query-small', $query), qr/HTTP\/1\.. 413/,
		'POST body too large - 413');

	# GET query > max_size -> 413
	like(doh_get('/dns-query-small', $query), qr/HTTP\/1\.. 413/,
		'GET query too large - 413');

	# GET max_size checks decoded size, not encoded
	my $short_query = dns_query('a.example.com', 1);
	like(doh_get('/dns-query-max-size-decoded', $short_query),
		qr/HTTP\/1\.. 200/,
		'doh_max_size limits decoded size, not base64url length');
};

like(doh_post('/dns-query-timeout', $query), qr/HTTP\/1\.. 504/,
	'Upstream timeout - 504');

like(doh_post('/dns-query-refused', $query), qr/HTTP\/1\.. 502/,
	'Upstream connection refused - 502');

# NXDOMAIN -> 200 + RCODE=3 + Cache-Control from SOA (subtest)
subtest 'NXDOMAIN response' => sub {
	my $resp = doh_post('/dns-query-nxdomain', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'DNS NXDOMAIN - HTTP 200');

	my $body  = doh_extract_body($resp);
	my $rcode = doh_rcode($body);
	is($rcode, 3, 'NXDOMAIN response RCODE=3');

	like($resp, qr/Cache-Control: max-age=3600/i,
		'No-answer Cache-Control from SOA authority section');
};

like(http(POST_req('/dns-query', $query,
	'Content-Type' => 'application/dns-message; charset=utf-8')),
	qr/HTTP\/1\.. 415/, 'POST Content-Type with params - 415');

subtest 'POST query ID preservation' => sub {
	my $resp = doh_post('/dns-query', $query);
	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'POST response query ID matches');
};

subtest 'GET with extra query params' => sub {
	my $encoded = encode_base64url($query);
	like(http_get("/dns-query?dns=$encoded&foo=bar"),
		qr/HTTP\/1\.. 200/, 'GET with extra query params - 200');
	like(http_get("/dns-query?foo=bar&dns=$encoded"),
		qr/HTTP\/1\.. 200/, 'GET dns param after other params - 200');
};

subtest 'base64url padding variants' => sub {
	my $padded_query = dns_query('a.b', 1);
	my $enc = encode_base64url($padded_query);
	$enc =~ s/=+$//;
	like(http_get("/dns-query?dns=$enc"), qr/HTTP\/1\.. 200/,
		'GET base64url 1-char padding - 200');

	$padded_query = dns_query('ab.cd', 1);
	$enc = encode_base64url($padded_query);
	$enc =~ s/=+$//;
	like(http_get("/dns-query?dns=$enc"), qr/HTTP\/1\.. 200/,
		'GET base64url 2-char padding - 200');
};

subtest 'UDP transport' => sub {
	like(doh_post('/dns-query-udp', $query), qr/HTTP\/1\.. 200/,
		'UDP POST valid query - status 200');

	like(doh_get('/dns-query-udp', $query), qr/HTTP\/1\.. 200/,
		'UDP GET valid query - status 200');

	my $resp = doh_post('/dns-query-udp', $query);
	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'UDP response query ID matches');
};

# UDP too-short response -> 502
like(doh_post('/dns-query-udp-short', $query), qr/HTTP\/1\.. 502/,
	'UDP response < 12 bytes - 502');

# UDP response > max_size -> 200 (max_size limits queries, not responses)
like(doh_post('/dns-query-udp-large', $query), qr/HTTP\/1\.. 200/,
	'UDP response > doh_max_size - 200 (max_size is query-only)');

# doh_next_upstream off — normal request still works
like(doh_post('/dns-query-no-retry', $query), qr/HTTP\/1\.. 200/,
	'doh_next_upstream off normal request - 200');

subtest 'client disconnect - next request still works' => sub {
	my $s = http_start(POST_req('/dns-query-timeout', $query,
		'Content-Type' => 'application/dns-message'), NoDelay => 1);

	$s->autoflush(1);
	select undef, undef, undef, 0.5;
	$s->close() if defined $s;

	like(doh_post('/dns-query', $query), qr/HTTP\/1\.. 200/,
		'request after client disconnect - 200');
};

like(doh_get('/dns-query-tcp-get', $query), qr/HTTP\/1\.. 200/,
	'GET with TCP transport - 200');

# doh_socket_keepalive -> 200
like(doh_post('/dns-query-keepalive', $query), qr/HTTP\/1\.. 200/,
	'POST with socket keepalive - 200');

# doh_connect_timeout -> 502
like(doh_post('/dns-query-connect-timeout', $query), qr/HTTP\/1\.. 502/,
	'Connect timeout - 502 Bad Gateway');

# doh_send_timeout -> 504
like(doh_post('/dns-query-send-timeout', $query), qr/HTTP\/1\.. 504/,
	'Send timeout - 504 Gateway Timeout');

subtest 'small client_body_buffer_size' => sub {
	my $resp = doh_post('/dns-query-small-buf', $query);

	# POST query still works (body read from temp file)
	like($resp, qr/HTTP\/1\.. 200/, 'small buf POST - status 200');
	like($resp, qr/Content-Type: application\/dns-message/i,
		'small buf POST - content type');

	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'small buf POST - query ID preserved');

	# GET still works (no body involved)
	like(doh_get('/dns-query-small-buf', $query), qr/HTTP\/1\.. 200/,
		'small buf GET - 200');
};

# client_body_in_file_only on — POST and GET queries still works
subtest 'client_body_in_file_only on' => sub {
	my $resp = doh_post('/dns-query-in-file-only', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'in_file_only POST - status 200');
	like($resp, qr/Content-Type: application\/dns-message/i,
		'in_file_only POST - content type');

	my $body = doh_extract_body($resp);
	my $query_id = doh_query_id($query);
	my $resp_id  = doh_query_id($body);
	is($resp_id, $query_id, 'in_file_only POST - query ID preserved');

	# client_body_in_file_only on — GET still works
	like(doh_get('/dns-query-in-file-only', $query), qr/HTTP\/1\.. 200/,
		'in_file_only GET - 200');
};

###############################################################################
