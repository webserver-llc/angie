#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for reusing a cached HTTP/3 upstream connection whose server advertised
# stream limit is already exhausted.  The bad connection must be closed and
# retried to the same peer instead of failing with 500.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite http_v3/)
	->has(qw/upstream_keepalive/)->has_daemon('openssl')->plan(33);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%%;

        keepalive 1;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_http_version        3;
            proxy_next_upstream       error timeout;
            add_header X-Upstream-Status "$upstream_status";

            proxy_pass https://u;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        # server dictates limit to client
        http3_max_concurrent_streams 1;

        location / {
            return 200 "backend::$quic_connection\n";
        }
    }
}

EOF

$t->run();

###############################################################################

my $res;

my $prev_num = -1;
my $conn_num;

# first request is within limit
$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 1 is 200');
($conn_num) = $res =~ /backend::(\d+)/;
isnt($conn_num, $prev_num, "new connection number: $conn_num");
$prev_num = $conn_num;
like($res, qr/X-Upstream-Status: 200/, "success on first request");

# the following requests reuse the cached connection, hit the stream limit and
# must be retried on a new upstream connection rather than failing with 500;
# additional check for new connection number verifies that we actually
# use new connection;
#
# There is a race between receiving MAX_STREAMS frame and retrying;
# there is no simple reliable method to avoid race, thus we try multiple
# times and expect both outcomes: hitting the limit and normal connection

for (my $i = 2; $i < 12; $i++) {

	$res = http_get('/');

	like($res, qr/HTTP\/1\.1 200/, "request $i is 200");
	($conn_num) = $res =~ /backend::(\d+)/;

	if ($res =~ qr/X-Upstream-Status: 502, 200/) {
		pass("new quic connection after stream limit hit");
		isnt($conn_num, $prev_num, "new quic connection is used: $conn_num");

	} elsif ($res =~ qr/X-Upstream-Status: 200/) {
		pass("got response from the same quic connection");
		is($conn_num, $prev_num, "old connection is used: $conn_num");

	} else {
		fail("unexpected response");
		last;
	}

	$prev_num = $conn_num;
}

###############################################################################
