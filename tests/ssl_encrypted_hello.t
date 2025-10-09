#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http ssl module, support for Encrypted Client Hello (ECH).

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl sni rewrite/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  public;

        ssl_certificate public.crt;
        ssl_certificate_key public.key;

        ssl_encrypted_hello_key public.ech;

        return 200 "$ssl_server_name:$ssl_encrypted_hello\n";
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  secret;

        ssl_certificate secret.crt;
        ssl_certificate_key secret.key;

        return 200 "$ssl_server_name:$ssl_encrypted_hello\n";
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  verify;

        ssl_certificate verify.crt;
        ssl_certificate_key verify.key;

        ssl_verify_client optional_no_ca;
        ssl_client_certificate verify.crt;

        return 200 "$ssl_server_name:$ssl_encrypted_hello:$ssl_client_verify\n";
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('public', 'secret', 'verify') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file(
	'trusted.crt',
	$t->read_file('public.crt')
	. $t->read_file('secret.crt')
	. $t->read_file('verify.crt')
);

if ((`openssl ech -help 2>&1` || '') =~ m/-public_name/) {

	# Generate ECH file with "openssl ech"

	system('openssl ech '
		. "-out $d/public.ech "
		. "-public_name public "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create ECH config: $!\n";

} elsif ((`bssl 2>&1` || '') =~ m/generate-ech/) {

	# Generate ECH file with "bssl generate-ech"
	# and additional manual formatting to produce a PEM file

	system('bssl generate-ech '
		. "-out-ech-config $d/public.echconfig.bin "
		. "-out-ech-config-list $d/public.echconfiglist.bin "
		. "-out-private-key $d/public.echkey.bin "
		. "-public-name public "
		. "-config-id 0 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create ECH config: $!\n";

	my $list = $t->read_file('public.echconfiglist.bin');
	my $key = $t->read_file('public.echkey.bin');

	# BoringSSL uses raw X25519 private key.  Convert it to PKCS#8
	# PrivateKeyInfo.

	$key = "\x30\x2E"			# SEQUENCE, 46 bytes
		. "\x02\x01\x00"		# INTEGER, 1 byte, 0
		. "\x30\x05"			# SEQUENCE, 5 bytes
		. "\x06\x03\x2B\x65\x6E"	# OBJECT, 3 bytes, X25519
		. "\x04\x22"			# OCTET STRING, 34 bytes
		. "\x04\x20"			# OCTET STRING, 32 bytes
		. $key;

	$t->write_file(
		'public.ech',
		"-----BEGIN PRIVATE KEY-----\n"
		. encode_base64($key)
		. "-----END PRIVATE KEY-----\n"
		. "-----BEGIN ECHCONFIG-----\n"
		. encode_base64($list)
		. "-----END ECHCONFIG-----\n"
	);

} else {
	plan(skip_all => 'no openssl ech or bssl generate-ech')
}

$t->try_run('no ssl_encrypted_hello_key')->plan(8);

###############################################################################

my ($cmd, $req, $out);
my $port = port(8443);

# ECH file looks like:
#
# -----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VuBCIEIMhvGkKTR2gchVcurYDocK4v1Y5wac20UZzB3JB0QMVh
# -----END PRIVATE KEY-----
# -----BEGIN ECHCONFIG-----
# AEX+DQBBGwAgACC2q1Z7YDL1X4bahRyJeBZb3bwHPITBUxqFBS2CIfXCGQAEAAEA
# AQAScHVibGljLmV4YW1wbGUub3JnAAA=
# -----END ECHCONFIG-----
#
# To use on the client we need ECHCONFIG part, which contains ECHConfigList
# structure.

my $config = $t->read_file('public.ech');
$config =~ s/.*-----BEGIN ECHCONFIG-----(.*)-----END.*/$1/s;
$config =~ s/[\n\r\s]//g;

# Requests to use

$t->write_file('req-secret', "GET / HTTP/1.0\nHost: secret\n\n");
$t->write_file('req-verify', "GET / HTTP/1.0\nHost: verify\n\n");

SKIP: {
skip 'no openssl client ech', 4
	if `openssl s_client -help 2>&1` !~ /-ech_config_list/;

# Tests with OpenSSL s_client from ECH feature branch

# Note that OpenSSL s_client prints confusing "ECH: BAD NAME: -102" status
# when it is not able to verify server certificate.  To make sure proper
# success is visible in the output, we therefore explicitly provide trusted
# root certificates.
#
# Further, with TLSv1.2 and older protocols enabled OpenSSL s_client currently
# creates incorrect inner ClientHello, which is rejected by BoringSSL with
# the following error on the server:
#
# ... [crit] ... SSL_do_handshake() failed (SSL: error:1000013a:SSL routines:
# OPENSSL_internal:INVALID_CLIENT_HELLO_INNER error:1000008a:SSL routines:
# OPENSSL_internal:DECRYPTION_FAILED)...
#
# As a workaround, we explicitly request TLSv1.3 only.

$cmd = "openssl s_client "
	. "-connect 127.0.0.1:$port "
	. "-servername secret "
	. "-ech_config_list $config "
	. "-tls1_3 "
	. "-CAfile $d/trusted.crt -ign_eof <$d/req-secret 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

TODO: {
local $TODO = 'OpenSSL too old'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& !$t->has_feature('openssl:3.6.0');
local $TODO = 'LibreSSL has no support yet'
	if $t->has_module('LibreSSL');

like($out, qr/^ECH: success.*secret:1$/ms, 'openssl client');

}

# Test without ECH, to make sure the $ssl_encrypted_hello variable
# is properly set.
#
# The test explicitly requests @SECLEVEL=0 for libraries without TLSv1.2
# support, such as OpenSSL 1.0.0.

$cmd = "openssl s_client "
	. "-connect 127.0.0.1:$port "
	. "-servername secret "
	. "-cipher DEFAULT:\@SECLEVEL=0 "
	. "-CAfile $d/trusted.crt -ign_eof <$d/req-secret 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/^ECH: NOT CONFIGURED.*secret:$/ms, 'openssl client no ech');

# Tests with client certificate verification,
# mostly to check if the $ssl_encrypted_hello variable is correct, notably
# with failed client certificate verification.
#
# Currently fails with OpenSSL ECH feature branch on the server,
# the error is as follows:
#
# ... [crit] ... SSL_do_handshake() failed (SSL: error:0A000100:SSL routines::
# missing fatal)...
#
# This is expected to be fixed by
# https://github.com/openssl/openssl/pull/28555.

TODO: {
local $TODO = 'OpenSSL broken verify'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& $t->has_feature('openssl:3.6.0');
local $TODO = 'OpenSSL too old'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& !$t->has_feature('openssl:3.6.0');
local $TODO = 'LibreSSL has no support yet'
	if $t->has_module('LibreSSL');

$cmd = "openssl s_client "
	. "-connect 127.0.0.1:$port "
	. "-servername verify "
	. "-ech_config_list $config "
	. "-cert $d/verify.crt "
	. "-key $d/verify.key "
	. "-tls1_3 "
	. "-CAfile $d/trusted.crt -ign_eof <$d/req-verify 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/^ECH: success.*verify:1:SUCCESS/ms, 'openssl client verify');

$cmd = "openssl s_client "
	. "-connect 127.0.0.1:$port "
	. "-servername verify "
	. "-ech_config_list $config "
	. "-cert $d/secret.crt "
	. "-key $d/secret.key "
	. "-tls1_3 "
	. "-CAfile $d/trusted.crt -ign_eof <$d/req-verify 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/^ECH: success.*verify:1:FAILED/ms,
	'openssl client verify failed');

}
}

SKIP: {
skip 'no bssl client ech', 4
	if (`bssl client -help 2>&1` || '') !~ /-ech-config-list/;

# Tests with BoringSSL bssl tool

# BoringSSL bssl tool uses a file with binary ECHConfigList
# representation.

$t->write_file('public.bin', decode_base64($config));

$cmd = "bssl client "
	. "-connect 127.0.0.1:$port "
	. "-server-name secret "
	. "-ech-config-list $d/public.bin "
	. "-root-certs $d/trusted.crt <$d/req-secret 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

TODO: {
local $TODO = 'OpenSSL too old'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& !$t->has_feature('openssl:3.6.0');
local $TODO = 'LibreSSL has no support yet'
	if $t->has_module('LibreSSL');

like($out, qr/Encrypted ClientHello: yes.*secret:1$/ms, 'bssl client');

}

# Test without ECH, to make sure the $ssl_encrypted_hello variable
# is properly set.
#
# The test explicitly requests TLSv1.0 for libraries without TLSv1.2
# support, such as OpenSSL 1.0.0.

$cmd = "bssl client "
	. "-connect 127.0.0.1:$port "
	. "-server-name secret "
	. "-min-version tls1 "
	. "-root-certs $d/trusted.crt <$d/req-secret 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/Encrypted ClientHello: no.*secret:$/ms, 'bssl client no ech');

# Tests with client certificate verification,
# mostly to check if the $ssl_encrypted_hello variable is correct, notably
# with failed client certificate verification.

TODO: {
local $TODO = 'OpenSSL broken verify'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& $t->has_feature('openssl:3.6.0');
local $TODO = 'OpenSSL too old'
	if $t->has_module('OpenSSL') && !$t->has_module('BoringSSL')
	&& !$t->has_feature('openssl:3.6.0');
local $TODO = 'LibreSSL has no support yet'
	if $t->has_module('LibreSSL');

$cmd = "bssl client "
	. "-connect 127.0.0.1:$port "
	. "-server-name verify "
	. "-ech-config-list $d/public.bin "
	. "-cert $d/verify.crt "
	. "-key $d/verify.key "
	. "-root-certs $d/trusted.crt <$d/req-verify 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/Encrypted ClientHello: yes.*verify:1:SUCCESS/ms,
	'bssl client verify');

$cmd = "bssl client "
	. "-connect 127.0.0.1:$port "
	. "-server-name verify "
	. "-ech-config-list $d/public.bin "
	. "-cert $d/secret.crt "
	. "-key $d/secret.key "
	. "-root-certs $d/trusted.crt <$d/req-verify 2>&1";

log_out($cmd);

$out = `$cmd`;

log_in($out);

like($out, qr/Encrypted ClientHello: yes.*verify:1:FAILED/ms,
	'bssl client verify failed');

}
}

###############################################################################
