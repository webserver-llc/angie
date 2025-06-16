#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for proxy protocol v2 TLVs beetween proxy and upstream server.

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

my $t = Test::Nginx->new()
	->has(qw/stream stream_return stream_map rewrite/)->plan(38)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    map $proxy_protocol_tlv_ssl $binary_present {
        "~\\x00" "true";
    }

    upstream u {
        server 127.0.0.1:8090;
    }

    server {
        listen 127.0.0.1:8081 proxy_protocol;

        proxy_pass u;
        proxy_protocol on;
        proxy_protocol_version 2;

        proxy_protocol_tlv alpn $proxy_protocol_tlv_alpn;
        proxy_protocol_tlv authority $proxy_protocol_tlv_authority;
        proxy_protocol_tlv unique_id $proxy_protocol_tlv_unique_id;
        proxy_protocol_tlv netns $proxy_protocol_tlv_netns;
        proxy_protocol_tlv ssl $proxy_protocol_tlv_ssl;
        proxy_protocol_tlv 0x03 $proxy_protocol_tlv_0x03;
        proxy_protocol_tlv 0xae $proxy_protocol_tlv_0xae;
    }

    server {
        listen 127.0.0.1:8082 proxy_protocol;

        proxy_pass u;
        proxy_protocol on;
        proxy_protocol_version 2;

        proxy_protocol_tlv alpn "AAALPN";
        proxy_protocol_tlv authority "AAAUTH";
        proxy_protocol_tlv unique_id "UUUNIQUE";
        proxy_protocol_tlv netns "NNNETNS";
        proxy_protocol_tlv 0x03 "54321";
        proxy_protocol_tlv 0xae "aeaeae";

        proxy_protocol_tlv ssl_verify "111";
        proxy_protocol_tlv ssl_version "55";
        proxy_protocol_tlv ssl_cn "CCCN";
        proxy_protocol_tlv ssl_0x23 "CCCIPHER";
        proxy_protocol_tlv ssl_sig_alg "SSSIG";
        proxy_protocol_tlv ssl_key_alg "KKKEY";

    }

    server {
        listen 127.0.0.1:8083 proxy_protocol;

        proxy_pass u;
        proxy_protocol on;
        proxy_protocol_version 2;

        proxy_protocol_tlv ssl_version "55";
        proxy_protocol_tlv ssl_cn "CCCN";
        proxy_protocol_tlv ssl_0x23 "CCCIPHER";
        proxy_protocol_tlv ssl_sig_alg "SSSIG";
        proxy_protocol_tlv ssl_key_alg "KKKEY";

        proxy_protocol_tlv alpn "AAALPN";
        proxy_protocol_tlv authority "AAAUTH";
        proxy_protocol_tlv unique_id "UUUNIQUE";
        proxy_protocol_tlv netns "NNNETNS";
        proxy_protocol_tlv 0x03 "54321";
        proxy_protocol_tlv 0xae "aeaeae";
    }

    server {
        listen 127.0.0.1:8090 proxy_protocol;
        return "
            alpn:$proxy_protocol_tlv_alpn
            authority:$proxy_protocol_tlv_authority
            crc32c:$proxy_protocol_tlv_0x3
            unique-id:$proxy_protocol_tlv_unique_id
            netns:$proxy_protocol_tlv_netns
            ssl-verify:$proxy_protocol_tlv_ssl_verify
            ssl-version:$proxy_protocol_tlv_ssl_version
            ssl-cn:$proxy_protocol_tlv_ssl_cn
            ssl-cipher:$proxy_protocol_tlv_ssl_cipher
            ssl-sig-alg:$proxy_protocol_tlv_ssl_sig_alg
            ssl-key-alg:$proxy_protocol_tlv_ssl_key_alg
            custom:$proxy_protocol_tlv_0x000ae
            x:$proxy_protocol_tlv_0x000e
            ssl-binary:$binary_present
            remote_addr:$remote_addr";
    }

}

EOF

$t->run();

###############################################################################

# TLVs without SSL

{
my $tlv = pp2_create_tlv(0x1, "ALPN1");
$tlv .= pp2_create_tlv(0x2, "localhost");
$tlv .= pp2_create_tlv(0x3, "4321");
$tlv .= pp2_create_tlv(0x5, "UNIQQ");
$tlv .= pp2_create_tlv(0x30, "NETNS");
$tlv .= pp2_create_tlv(0xae, "12345");
my $p = pp2_create($tlv);

my $r = pp_get(8081, $p);
like($r, qr/alpn:ALPN1\x0d?$/m, 'ALPN');
like($r, qr/authority:localhost\x0d?$/m, 'AUTHORITY');
like($r, qr/crc32c:4321\x0d?$/m, 'CRC32C');
like($r, qr/unique-id:UNIQQ\x0d?$/m, 'UNIQUE_ID');
like($r, qr/netns:NETNS\x0d?$/m, 'NETNS');
like($r, qr/custom:12345\x0d?$/m, 'custom');
like($r, qr/x:\x0d?$/m, 'non-existent');

SKIP: {
skip 'no PCRE', 1 unless $t->has_module('pcre');

unlike($r, qr/ssl-binary:true/, 'SSL_BINARY');
}

}

# SSL subtype TLVs

{
my $sub = pp2_create_tlv(0x21, "TLSv1.2");
$sub .= pp2_create_tlv(0x22, "example.com");
$sub .= pp2_create_tlv(0x23, "AES256-SHA");
$sub .= pp2_create_tlv(0x24, "SHA1");
$sub .= pp2_create_tlv(0x25, "RSA512");
my $ssl = pp2_create_ssl(0x01, 255, $sub);
my $tlv .= pp2_create_tlv(0x20, $ssl);
my $p = pp2_create($tlv);

my $r = pp_get(8081, $p);
like($r, qr/ssl-verify:255\x0d?$/m, 'SSL_VERIFY');
like($r, qr/ssl-version:TLSv1.2\x0d?$/m, 'SSL_VERSION');
like($r, qr/ssl-cn:example.com\x0d?$/m, 'SSL_CN');
like($r, qr/ssl-cipher:AES256-SHA\x0d?$/m, 'SSL_CIPHER');
like($r, qr/ssl-sig-alg:SHA1\x0d?$/m, 'SSL_SIG_ALG');
like($r, qr/ssl-key-alg:RSA512\x0d?$/m, 'SSL_KEY_ALG');

SKIP: {
skip 'no PCRE', 1 unless $t->has_module('pcre');

like($r, qr/ssl-binary:true/, 'SSL_BINARY');
}

}

# TLVs generated by proxy

{
my $tlv = pp2_create_tlv(0x1, "ALPN1");
$tlv .= pp2_create_tlv(0x2, "localhost");
$tlv .= pp2_create_tlv(0x3, "4321");
$tlv .= pp2_create_tlv(0x5, "UNIQQ");
$tlv .= pp2_create_tlv(0x30, "NETNS");
$tlv .= pp2_create_tlv(0xae, "12345");

my $sub = pp2_create_tlv(0x21, "TLSv1.2");
$sub .= pp2_create_tlv(0x22, "example.com");
$sub .= pp2_create_tlv(0x23, "AES256-SHA");
$sub .= pp2_create_tlv(0x24, "SHA1");
$sub .= pp2_create_tlv(0x25, "RSA512");
my $ssl = pp2_create_ssl(0x01, 255, $sub);
$tlv .= pp2_create_tlv(0x20, $ssl);

my $p = pp2_create($tlv);

my $r = pp_get(8082, $p);
like($r, qr/alpn:AAALPN\x0d?$/m, 'ALPN');
like($r, qr/authority:AAAUTH\x0d?$/m, 'AUTHORITY');
like($r, qr/crc32c:54321\x0d?$/m, 'CRC32C');
like($r, qr/unique-id:UUUNIQUE\x0d?$/m, 'UNIQUE_ID');
like($r, qr/netns:NNNETNS\x0d?$/m, 'NETNS');
like($r, qr/custom:aeaeae\x0d?$/m, 'custom');

like($r, qr/ssl-verify:111\x0d?$/m, 'SSL_VERIFY');
like($r, qr/ssl-version:55\x0d?$/m, 'SSL_VERSION');
like($r, qr/ssl-cn:CCCN\x0d?$/m, 'SSL_CN');
like($r, qr/ssl-cipher:CCCIPHER\x0d?$/m, 'SSL_CIPHER');
like($r, qr/ssl-sig-alg:SSSIG\x0d?$/m, 'SSL_SIG_ALG');
like($r, qr/ssl-key-alg:KKKEY\x0d?$/m, 'SSL_KEY_ALG');
}

# TLVs generated by proxy without verify

{
my $tlv = pp2_create_tlv(0x1, "ALPN1");
$tlv .= pp2_create_tlv(0x2, "localhost");
$tlv .= pp2_create_tlv(0x3, "4321");
$tlv .= pp2_create_tlv(0x5, "UNIQQ");
$tlv .= pp2_create_tlv(0x30, "NETNS");
$tlv .= pp2_create_tlv(0xae, "12345");

my $sub = pp2_create_tlv(0x21, "TLSv1.2");
$sub .= pp2_create_tlv(0x22, "example.com");
$sub .= pp2_create_tlv(0x23, "AES256-SHA");
$sub .= pp2_create_tlv(0x24, "SHA1");
$sub .= pp2_create_tlv(0x25, "RSA512");
my $ssl = pp2_create_ssl(0x01, 255, $sub);
$tlv .= pp2_create_tlv(0x20, $ssl);

my $p = pp2_create($tlv);

my $r = pp_get(8082, $p);
like($r, qr/alpn:AAALPN\x0d?$/m, 'ALPN');
like($r, qr/authority:AAAUTH\x0d?$/m, 'AUTHORITY');
like($r, qr/crc32c:54321\x0d?$/m, 'CRC32C');
like($r, qr/unique-id:UUUNIQUE\x0d?$/m, 'UNIQUE_ID');
like($r, qr/netns:NNNETNS\x0d?$/m, 'NETNS');
like($r, qr/custom:aeaeae\x0d?$/m, 'custom');

like($r, qr/ssl-version:55\x0d?$/m, 'SSL_VERSION');
like($r, qr/ssl-cn:CCCN\x0d?$/m, 'SSL_CN');
like($r, qr/ssl-cipher:CCCIPHER\x0d?$/m, 'SSL_CIPHER');
like($r, qr/ssl-sig-alg:SSSIG\x0d?$/m, 'SSL_SIG_ALG');
like($r, qr/ssl-key-alg:KKKEY\x0d?$/m, 'SSL_KEY_ALG');
}

###############################################################################

sub pp_get {
	my ($port, $proxy) = @_;
	stream(PeerPort => port($port))->io($proxy);
}

sub pp2_create {
	my ($tlv) = @_;

	my $pp2_sig = pack("N3", 0x0D0A0D0A, 0x000D0A51, 0x5549540A);
	my $ver_cmd = pack('C', 0x21);
	my $family = pack('C', 0x11);
	my $packet = $pp2_sig . $ver_cmd . $family;

	my $ip1 = pack('N', 0xc0000201); # 192.0.2.1
	my $ip2 = pack('N', 0xc0000202); # 192.0.2.2
	my $port1 = pack('n', 123);
	my $port2 = pack('n', 5678);
	my $addrs = $ip1 . $ip2 . $port1 . $port2;

	my $len = length($addrs) + length($tlv);

	$packet .= pack('n', $len) . $addrs . $tlv;

	return $packet;
}

sub pp2_create_tlv {
	my ($type, $content) = @_;

	my $len = length($content);

	return pack("CnA*", $type, $len, $content);
}

sub pp2_create_ssl {
	my ($client, $verify, $content) = @_;

	return pack("CNA*", $client, $verify, $content);
}

###############################################################################
