#!/usr/bin/perl

# (C) Roman Arutyunyan
# (C) Eugene Grebenschikov
# (C) Nginx, Inc.

# Tests for variables for proxy protocol v2 TLVs.

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

my $t = Test::Nginx->new()->has(qw/http access rewrite/)->plan(15)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $proxy_protocol_tlv_ssl $binary_present {
        "~\\x00" "true";
    }

    add_header X-ALPN
        $proxy_protocol_tlv_alpn-$proxy_protocol_tlv_0x01;
    add_header X-AUTHORITY
        $proxy_protocol_tlv_authority-$proxy_protocol_tlv_0x02;
    add_header X-UNIQUE-ID
        $proxy_protocol_tlv_unique_id-$proxy_protocol_tlv_0x05;
    add_header X-NETNS
        $proxy_protocol_tlv_netns-$proxy_protocol_tlv_0x30;
    add_header X-SSL-VERIFY
        $proxy_protocol_tlv_ssl_verify;
    add_header X-SSL-VERSION
        $proxy_protocol_tlv_ssl_version-$proxy_protocol_tlv_ssl_0x21;
    add_header X-SSL-CN
        $proxy_protocol_tlv_ssl_cn-$proxy_protocol_tlv_ssl_0x22;
    add_header X-SSL-CIPHER
        $proxy_protocol_tlv_ssl_cipher-$proxy_protocol_tlv_ssl_0x23;
    add_header X-SSL-SIG-ALG
        $proxy_protocol_tlv_ssl_sig_alg-$proxy_protocol_tlv_ssl_0x24;
    add_header X-SSL-KEY-ALG
        $proxy_protocol_tlv_ssl_key_alg-$proxy_protocol_tlv_ssl_0x25;
    add_header X-TLV-CRC32C
        $proxy_protocol_tlv_0x3;
    add_header X-TLV-CUSTOM
        $proxy_protocol_tlv_0x000ae;
    add_header X-TLV-X
        $proxy_protocol_tlv_0x000e-$proxy_protocol_tlv_0x0f;
    add_header X-SSL-BINARY
        $binary_present;

    server {
        listen       127.0.0.1:8080 proxy_protocol;
        server_name  localhost;

        location / { return 200; }
    }
}

EOF

$t->run();

###############################################################################

my $p = pack("N3C", 0x0D0A0D0A, 0x000D0A51, 0x5549540A, 0x21);
my $tlv = $p . pack("CnN2n2N21nN2nN2nN4", 0x11, 134, 0xc0000201, 0xc0000202,
	123, 5678,
	# 0x01 alpn
	0x01000541, 0x4c504e31,
	# 0x02 authority
	0x0200096c, 0x6f63616c, 0x686f7374,
	# 0x03 crc32
	0x03000534, 0x33323130,
	# 0x05 unique_id
	0x05000555, 0x4e495151,
	# 0x20 ssl
	0x20004301, 0x000000ff,
	# 0x21 ssl_version
	0x21000132,
	# 0x22 ssl_cn
	0x22000541, 0x42433435,
	# 0x23 ssl_cipher
	0x23001b45, 0x43444845, 0x2d525341, 0x2d414553, 0x3132382d, 0x47434d2d,
	0x53484132, 0x3536,
	# 0x24 ssl_sig_alg
	0x24000753, 0x48413130, 0x3234,
	# 0x25 ssl_key_alg
	0x25000752, 0x53413230, 0x3438,
	# 0x30 netns
	0x3000054e, 0x45544e53,
	# 0xae custom
	0xae000531, 0x32333435);
my $r;

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.23.2');

$r = pp_get('/t1', $tlv);
like($r, qr/X-ALPN: ALPN1-ALPN1\x0d/, 'ALPN - tlv named variable');
like($r, qr/X-AUTHORITY: localhost-localhost\x0d/,
	'AUTHORITY - tlv named variable');
like($r, qr/X-UNIQUE-ID: UNIQQ-UNIQQ\x0d/, 'UNIQUE_ID - tlv named variable');
like($r, qr/X-NETNS: NETNS-NETNS\x0d/, 'NETNS - tlv named variable');
like($r, qr/X-SSL-BINARY: true/, 'SSL_BINARY - tlv named variable');
like($r, qr/X-SSL-VERIFY: 255\x0d/, 'SSL_VERIFY - tlv named variable');
like($r, qr/X-SSL-VERSION: 2-2\x0d/, 'SSL_VERSION - tlv named variable');
like($r, qr/X-SSL-CN: ABC45-ABC45\x0d/, 'SSL_CN - tlv named variable');
like($r, qr/X-SSL-CIPHER: ECDHE-RSA-AES128-GCM-SHA256/,
	'SSL_CIPHER - tlv named variable (part 1)');
like ($r, qr/-ECDHE-RSA-AES128-GCM-SHA256\x0d/,
	'SSL_CIPHER - tlv named variable (part 2)');
like($r, qr/X-SSL-SIG-ALG: SHA1024-SHA1024\x0d/,
	'SSL_SIG_ALG - tlv named variable');
like($r, qr/X-SSL-KEY-ALG: RSA2048-RSA2048\x0d/,
	'SSL_KEY_ALG - tlv named variable');
like($r, qr/X-TLV-CRC32C: 43210\x0d/, 'CRC32C - tlv numeric variable');
like($r, qr/X-TLV-CUSTOM: 12345\x0d/,
	'custom - tlv numeric variable');
like($r, qr/X-TLV-X: -\x0d/, 'non-existent - tlv numeric variable');

}

###############################################################################

sub pp_get {
	my ($url, $proxy) = @_;
	return http($proxy . <<EOF);
GET $url HTTP/1.0
Host: localhost

EOF
}

###############################################################################
