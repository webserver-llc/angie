#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for stream_mqtt_preread module.

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

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_mqtt_preread/)
	->plan(11)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;
        mqtt_preread on;
        return "
            username:$mqtt_preread_username
            clientid:$mqtt_preread_clientid";
    }
}

EOF

$t->run();

###############################################################################

my $p1 = pack('CN*', 0x10, 0x3500044d, 0x51545405, 0xc6003c05);
$p1 .= pack('N*', 0x11000007, 0x08000474, 0x65737404);
$p1 .= pack('N*', 0x51515151, 0x00047575, 0x75750002);
$p1 .= pack('N*', 0x73730004, 0x75757575, 0x00087061);
$p1 .= pack('Nn', 0x7373776f, 0x7264);

my $r = send_packet($p1);
like($r, qr/username:uuuu\s+clientid:test$/m, 'basic CONNECT MQTTv5');

$r = send_packet(connect_basic(5, "foo", ""));
like($r, qr/username:\s+clientid:foo$/m, 'client_id CONNECT MQTTv5');

$r = send_packet(connect_basic(4, "foo", ""));
like($r, qr/username:\s+clientid:foo$/m, 'client_id CONNECT MQTTv3.1.1');

$r = send_packet(connect_basic(5, "", "bar"));
like($r, qr/username:bar\s+clientid:$/m, 'username CONNECT MQTTv5');

$r = send_packet(connect_basic(4, "", "bar"));
like($r, qr/username:bar\s+clientid:$/m, 'username CONNECT MQTTv3.1.1');

SKIP: {

skip "no --with-debug", 6 unless $t->has_module('--with-debug');

my @bytes = (
	pack('c', 0x00), pack('n', 0x00), pack('C', 0xff),
	pack('c', 0x03), pack('c', 0x01), pack('N', 0xffffffff)
);
my @offsets = (0, 5, 12, 8, 9, 1);

my $tmp;

for my $i (0..scalar(@offsets) - 1) {
	$tmp = $p1;
	substr($tmp, $offsets[$i], length($bytes[$i])) = $bytes[$i];
	send_packet($tmp);
}

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/not a CONNECT/, 'packet type');
like($log, qr/bad protocol name/, 'protocol name');
like($log, qr/bad protocol version/, 'protocol version');
like($log, qr/\"reserved\" flag set/, 'flags');
like($log, qr/parse remaining/, 'remaining length');
like($log, qr/parse properties length/, 'properties');

}

###############################################################################

sub send_packet {
	my ($bytes) = @_;
	stream('127.0.0.1:' . port(8081))->io($bytes);
}

sub connect_basic {
	my ($version, $client_id, $username) = @_;
	my ($ul, $cl) = (length($username) , length($client_id));

	my ($f) = 2;
	$f |= 0x80 if $ul;

	my ($vh) = pack('nNC2n', 0x04, 0x4d515454, $version, $f, 0x00);
	$vh .= pack('c', 0x00) if $version eq 5;

	my $p = pack('n', $cl) . $client_id;
	$p .= pack('n', $ul) . $username if $ul;
	$vh .= $p;

	my $packet = pack('C', 0x10);
	$packet .= get_varbyte(length($vh)) . $vh;

	return $packet;
}

sub get_varbyte {
	my ($x) = @_;
	my ($b, $o);

	do {
		$b = $x % 128;
		$x = int($x / 128);
		$b = $b | 128 if $x > 0;
		$o .= pack('C', $b)
	} while ($x > 0);

	return $o;
}

###############################################################################
