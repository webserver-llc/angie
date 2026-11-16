#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for TLS early data with HTTP/2.

###############################################################################

use warnings;
use strict;

use IPC::Open3;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api http_ssl http_v2 rewrite/)
	->has_daemon('openssl');

plan(skip_all => 'no TLSv1.3 sessions in LibreSSL')
	if $t->has_module('LibreSSL');
plan(skip_all => 'no ALPN support in OpenSSL')
	if $t->has_module('OpenSSL') and not $t->has_feature('openssl:1.0.2');
plan(skip_all => 'no early data support in OpenSSL')
	if $t->has_module('OpenSSL') and not $t->has_feature('openssl:1.1.1');

$t->plan(18)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    # early data happens at resumed ssl connection, so we need sessions
    ssl_session_cache shared:SSL:1m;

    keepalive_timeout 0;

    server {
        listen      127.0.0.1:8080;

        location /status/ {
            api /status/;
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;
        status_zone  ssl_early_data_on;

        http2 on;
        ssl_early_data on;

        location /early {
            return 200 "EARLY: sess=$ssl_session_reused early=$ssl_early_data\n";
        }
        location /regular {
            return 200 "REGULAR: sess=$ssl_session_reused early=$ssl_early_data\n";
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;
        status_zone  ssl_early_data_off;

        http2 on;
        ssl_early_data off;

        location /early {
            return 200 "EARLY: sess=$ssl_session_reused early=$ssl_early_data\n";
        }
        location /regular {
            return 200 "REGULAR: sess=$ssl_session_reused early=$ssl_early_data\n";
        }
    }
}

EOF


my $d = $t->testdir();

my $sess1 = "$d/session1.txt";
my $sess2 = "$d/session2.txt";
my $early = "$d/req.txt";

$t->prepare_ssl();
$t->run();

my ($p1, $p2) = (port(8081), port(8082));

$t->waitforsocket("127.0.0.1:$p1");
$t->waitforsocket("127.0.0.1:$p2");

###############################################################################

# HTTP/2 client connection preface
my $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

# HEADERS frame, stream 1, END_STREAM|END_HEADERS:
#   0x82 - :method GET (indexed)
#   0x87 - :scheme https (indexed)
#   0x41 - literal with incremental indexing, name index 1 (:authority)
#   0x09 "localhost" - authority value
#   0x83 - :path /early ... (indexed only for '/', so use literal)
# :path as literal without indexing, name index 4:
#   0x04 - literal without indexing, name index 4 (:path)
#   len + "/early"

my $hpack_early = "\x82\x87\x41" . pack('C', length 'localhost')
	. 'localhost' . "\x04" . pack('C', length '/early') . '/early';
my $hpack_regular = "\x82\x87\x41" . pack('C', length 'localhost')
	. 'localhost' . "\x04" . pack('C', length '/regular') . '/regular';

my $req_early = $preface . h2_frame(0x4, 0, 0, '')
	. h2_frame(0x1, 0x5, 1, $hpack_early);
my $req_regular = $preface . h2_frame(0x4, 0, 0, '')
	. h2_frame(0x1, 0x5, 1, $hpack_regular);

$t->write_file("req.txt", $req_early);

# server 1: ssl_early_data on

my $before1 = get_ssl_stats('ssl_early_data_on');

# 1st request: establish session and save it
my $r1 = early_get($p1, "-no_ticket -sess_out $sess1", $req_regular);
like($r1, qr/REGULAR/, "initial response from $p1");
like($r1, qr/\ssess=\.\s?/, "new session (not reused) on $p1");
unlike($r1, qr/\searly=1/,
	"no \$ssl_early_data variable on initial handshake $p1");

# 2nd request: resume session and pass request via early data
my $r2 = early_get($p1, "-early_data $early -sess_in $sess1", "");
like($r2, qr/EARLY/, "resume and early data $p1");
like($r2, qr/\ssess=r\s?/, "session reused on $p1");

TODO: {
	local $TODO = 'race: SSL_is_init_finished() may be true by response time';
	like($r2, qr/\searly=1/im, "\$ssl_early_data variable set for $p1");
}

my $after1 = get_ssl_stats('ssl_early_data_on');

is($after1->{handshaked} - $before1->{handshaked}, 2,
	'stats: 2 successful handshakes counted (on)');
is($after1->{reuses} - $before1->{reuses}, 1,
	'stats: 1 session reuse counted (on, via early data)');
is($after1->{failed}, $before1->{failed}, 'stats: no failed handshakes (on)');

# server 2: ssl_early_data off

my $before2 = get_ssl_stats('ssl_early_data_off');

# 3rd request: establish session to server with early_data disabled
my $r3 = early_get($p2, "-no_ticket -sess_out $sess2", $req_regular);
like($r3, qr/REGULAR/, "initial response from $p2");
like($r3, qr/\ssess=\.\s?/, "new session (not reused) on $p2");
unlike($r3, qr/\searly=1/,
	"no \$ssl_early_data variable on initial handshake $p2");

# 4th request: early data rejected, regular request goes through
$t->write_file("req.txt", $req_regular);
my $r4 = early_get($p2, "-early_data $early -sess_in $sess2", $req_regular);
like($r4, qr/REGULAR/, "response from $p2 no early");
like($r4, qr/\ssess=r\s?/, "session reused (via regular 1-RTT) on $p2");
unlike($r4, qr/\searly=1/, "\$ssl_early_data variable not set for $p2");

my $after2 = get_ssl_stats('ssl_early_data_off');

is($after2->{handshaked} - $before2->{handshaked}, 2,
	'stats: 2 successful handshakes counted (off)');
is($after2->{reuses} - $before2->{reuses}, 1,
	'stats: 1 session reuse counted (off, via regular 1-RTT)');
is($after2->{failed}, $before2->{failed}, 'stats: no failed handshakes (off)');

###############################################################################

# build frame header explicitly
sub h2_frame {
	my ($type, $flags, $sid, $payload) = @_;
	my $len = pack('N', length $payload);
	substr($len, 0, 1) = '';
	return $len . pack('CC', $type, $flags)
		. pack('N', $sid & 0x7fffffff) . $payload;
}

sub early_get {
	my ($p, $args, $payload) = @_;

	my $cmd = "openssl s_client -connect localhost:$p -alpn h2 "
			. "-quiet -ign_eof $args";
	my $pid = open3(my $ssl_in, my $ssl_out, my $ssl_err, $cmd)
		or die "Can't run openssl: $!";

	binmode($ssl_in);
	print $ssl_in $payload;

	my $r;
	while (<$ssl_out>) { $r .= $_ }

	waitpid($pid, 0);

	return $r;
}

sub get_ssl_stats {
	my ($zone) = @_;
	return get_json("/status/http/server_zones/$zone/ssl");
}

###############################################################################
