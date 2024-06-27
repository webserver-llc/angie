#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for stream_rdp_preread module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_rdp_preread/)
	->plan(10)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
	%%TEST_GLOBALS_STREAM%%

	rdp_preread on;

	server {
		listen 127.0.0.1:8081;
		return $rdp_cookie;
	}

	server {
		listen 127.0.0.1:8082;
		return $rdp_cookie_mstshash;
	}

	server {
		listen 127.0.0.1:8083;
		return $rdp_cookie_msts;
	}

	server {
		listen 127.0.0.1:8084;
		return $rdp_cookie_angieangieangie;
	}
}

EOF

$t->run();

###############################################################################

my ($p, $r);

$p = pack('N*', 0x47455420, 0x2f204854, 0x54500a43, 0x6f6f6b69);
$p .= pack('N*', 0x653a206d, 0x73747368, 0x6173683d, 0x616e6769);
$p .= pack('N*', 0x650d0a41, 0x63636570, 0x743a202a, 0x2f2a0d0a);

$r = send_packet($p, port(8081));
like($r, qr/$/, 'not a rdp');

$p = pack('N*', 0x03000013, 0x0ee00000, 0x00000001);
$p .= pack('NnC', 0x00080003, 0x0000, 0x00);

$r = send_packet($p, port(8081));
like($r, qr/$/, 'empty cookie');

$p = pack('N*', 0x0300002b, 0x27e00000, 0x00000043, 0x6f6f6b69);
$p .= pack('N*', 0x653a206d, 0x73747368, 0x6173683d, 0x616e6769);
$p .= pack('N2nC', 0x650d0a01, 0x00080003, 0x0000, 0x00);

$r = send_packet($p, port(8081));
like($r, qr/mstshash=angie$/m, 'rdp cookie');

$r = send_packet($p, port(8082));
like($r, qr/angie$/m, 'named cookie');

$r = send_packet($p, port(8083));
like($r, qr/$/, 'cookie not found 1');

$r = send_packet($p, port(8084));
like($r, qr/$/, 'cookie not found 2');

SKIP: {

skip "no --with-debug", 4 unless $t->has_module('--with-debug');

my @bytes = (
	pack('C', 0x00), pack('C', 0xff),
	pack('n', 0x0010), pack('n', 0x00)
);
my @offsets = (0, 1, 2, 33);

for my $i (0..scalar(@offsets) - 1) {
	my $tmp = $p;
	substr($tmp, $offsets[$i], length($bytes[$i]), $bytes[$i]);
	send_packet($tmp, port(8081));
}

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/TPKT packet header/, 'packet header 1');
like($log, qr/bad reserved byte/, 'packet header 2');
like($log, qr/empty cookie/, 'packet cookie 1');
like($log, qr/bad cookie/, 'packet cookie 2');
}

###############################################################################

sub send_packet {
	my ($bytes, $port) = @_;
	return stream('127.0.0.1:' . $port)->io($bytes);
}

###############################################################################
