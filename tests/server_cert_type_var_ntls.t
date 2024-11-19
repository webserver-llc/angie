#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for "ssl_server_cert_type" variable NTLS.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

use IPC::Open3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $openssl = $ENV{'TEST_ANGIE_OPENSSL_BINARY'} || 'openssl';

plan(skip_all => 'no NTLS client')
	if `$openssl s_client -help 2>&1` !~ /-ntls/m;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl ntls/)
	->has_daemon("$openssl")->plan(10)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format empty $ssl_server_cert_type;

    server {
        listen 127.0.0.1:8441 ssl;
        ssl_ntls on;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8442 ssl;
        ssl_ntls on;

        ssl_certificate_key ecdsa.key;
        ssl_certificate ecdsa.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8443 ssl;
        ssl_ntls on;

        ssl_certificate_key rsa-pss.key;
        ssl_certificate rsa-pss.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8444 ssl;
        ssl_ntls on;

        ssl_certificate_key ed448.key;
        ssl_certificate ed448.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8445 ssl;
        ssl_ntls on;

        ssl_certificate_key ed25519.key;
        ssl_certificate ed25519.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen  127.0.0.1:8500;
        listen  127.0.0.1:8446 ssl;

        ssl_certificate_key rsa.key;
        ssl_certificate     rsa.crt;

        ssl_certificate_key ecdsa.key;
        ssl_certificate     ecdsa.crt;

        ssl_ntls  on;
        ssl_certificate        server_sign.crt server_enc.crt;
        ssl_certificate_key    server_sign.key server_enc.key;

        ssl_trusted_certificate     client_ca_chain.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }

        location /proxy {
            proxy_ssl_ntls on;

            proxy_ssl_certificate        client_sign.crt client_enc.crt;
            proxy_ssl_certificate_key    client_sign.key client_enc.key;

            proxy_ssl_trusted_certificate     server_ca_chain.crt;


            proxy_ssl_ciphers "ECC-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-SM3:RSA";

            proxy_pass https://127.0.0.1:8446/;
        }
    }

    server {
        listen 127.0.0.1:8447 ssl;
        ssl_ntls on;

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        ssl_certificate_key ecdsa.key;
        ssl_certificate ecdsa.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8448 ssl;
        ssl_ntls on;

        access_log %%TESTDIR%%/empty.log empty;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        location / {
            return 200;
        }
    }

    server {
        listen 127.0.0.1:8449;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $tdir = $t->testdir();

my @types = ('rsa');

if ($t->has_feature('openssl:1.1.1')) {
	push(@types, ('rsa-pss', 'ed448', 'ed25519'));
}

foreach my $type (@types) {
	system("$openssl genpkey -algorithm $type -out $tdir/$type.key "
		. ">> $tdir/openssl.out 2>&1") == 0
		or die "Can't create '$type' key$!\n";

	system("$openssl req -new -config $tdir/openssl.conf "
		. "-subj /CN=$type/ -key $tdir/$type.key -x509 -nodes "
		. "-days 365 -out $tdir/$type.crt "
		. ">> $tdir/openssl.out 2>&1") == 0
		or die "Can't create '$type' cecertificate: $!\n";
}

# ECDSA
system("$openssl ecparam -name secp384r1 -genkey -out $tdir/ecdsa.key "
		. ">> $tdir/openssl.out 2>&1") == 0
	or die "Can't create 'ecdsa' key$!\n";

system("$openssl req -new -config $tdir/openssl.conf "
	. "-subj /CN=ecdsa/ -key $tdir/ecdsa.key -x509 -nodes "
	. "-days 365 -out $tdir/ecdsa.crt "
	. ">> $tdir/openssl.out 2>&1") == 0
	or die "Can't create 'ecdsa' cecertificate: $!\n";

gen_sm2($t, 'server');
gen_sm2($t, 'client');

$t->run();

###############################################################################

like(https_get(8441), qr/RSA/, 'RSA certificate');
like(https_get(8442), qr/ECDSA/, 'ECDSA certificate');

SKIP: {
skip 'OpenSSL too old', 3
	if $t->has_module('OpenSSL')
	and not $t->has_feature('openssl:1.1.1');

like(https_get(8443), qr/RSA-PSS/, 'RSA-PSS certificate');
like(https_get(8444), qr/ED448/, 'ED448 certificate');
like(https_get(8445), qr/ED25519/, 'ED25519 certificate');

like(http_get('/proxy', PeerAddr => '127.0.0.1:' . port(8500)),
	qr/SM2/, 'SM2 certificate');
}

like(https_cipher_get(8447, 'ECDHE-RSA-AES128-GCM-SHA256'),
	qr/RSA/, 'RSA certificate');

like(https_cipher_get(8447, 'ECDHE-ECDSA-AES128-SHA'),
	qr/ECDSA/, 'ECDSA certificate');

my $s = stream('127.0.0.1:' . port(8448));

$s->io('test');

for (1 .. 50) {
	last if -s "$tdir/empty.log";
	select undef, undef, undef, 0.1;
}

is($t->read_file('empty.log'), "-\n", 'Empty variable');

like(http_get('/', PeerAddr => '127.0.0.1:' . port(8449)),
	qr/-/, 'Empty variable');

###############################################################################

sub https_get {
	my ($port) = @_;
	return http_get('/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1);
}

sub https_cipher_get {
	my ($port, $cipher) = @_;
	return http_get('/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_cipher_list => $cipher);
}

sub gen_sm2 {
	my ($t, $type) = @_;

	my $ca = "${type}_ca";
	my $ca_cnf = "${type}_ca.cnf";
	my $subca = "${type}_subca";
	my $subca_cnf = "${type}_subca.cnf";

	$t->write_file($ca_cnf, <<EOF);
[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $tdir/$ca/newcerts
database = $tdir/$ca/certindex
serial = $tdir/$ca/certserial
default_days = 3

# The root key and root certificate.
private_key = $tdir/$ca/ca.key
certificate = $tdir/$ca/ca.crt

default_md = sha256

policy = myca_policy

[ myca_policy ]
commonName = supplied

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

	mkdir("$tdir/$ca");
	mkdir("$tdir/$ca/newcerts");

	$t->write_file("$ca/certserial", '1000');
	$t->write_file("$ca/certindex", '');

	system("$openssl ecparam -genkey -name SM2 "
		. "-out $tdir/$ca.key "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate CA key: $!\n";

	system("$openssl req -config $tdir/$ca_cnf "
		. "-new -key $tdir/$ca.key "
		. "-out $tdir/$ca.csr "
		. '-sm3 -nodes -sigopt sm2_id:1234567812345678 '
		. "-subj /CN=${type}_root_ca "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate CA csr: $!\n";

	system("$openssl ca -batch -selfsign "
		. "-config $tdir/$ca_cnf "
		. "-in $tdir/$ca.csr -keyfile $tdir/$ca.key "
		. '-extensions v3_ca -notext -md sm3 '
		. "-out $tdir/$ca.crt "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate CA crt: $!\n";

	$t->write_file($subca_cnf, <<EOF);
[ ca ]
default_ca = mysubca

[ mysubca ]
new_certs_dir = $tdir/$subca/newcerts
database = $tdir/$subca/certindex
serial = $tdir/$subca/certserial
default_days = 3
unique_subject = no

# The root key and root certificate.
private_key = $tdir/$subca/subca.key
certificate = $tdir/$subca/subca.crt

default_md = sha256

policy = myca_policy

[ myca_policy ]
commonName = supplied

[ sign_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature

[ enc_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = keyAgreement, keyEncipherment, dataEncipherment

[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]

EOF

	mkdir("$tdir/$subca");
	mkdir("$tdir/$subca/newcerts");

	$t->write_file("$subca/certserial", '1000');
	$t->write_file("$subca/certindex", '');

	system("$openssl ecparam -genkey -name SM2 "
		. "-out $tdir/$subca.key "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't genearate sub CA key: $!\n";

	system("$openssl req -config $tdir/$ca_cnf "
		. "-new -key $tdir/$subca.key "
		. "-out $tdir/$subca.csr "
		. '-sm3 -nodes -sigopt sm2_id:1234567812345678 '
		. "-subj /CN=${type}_sub_ca "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate sub CA csr: $!\n";

	system("$openssl ca -batch "
		. "-config $tdir/$ca_cnf "
		. "-in $tdir/$subca.csr "
		. "-cert $tdir/$ca.crt -keyfile $tdir/$ca.key "
		. '-extensions v3_intermediate_ca -notext -md sm3 '
		. "-out $tdir/$subca.crt "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate sub CA crt: $!\n";


	system("$openssl ecparam -name SM2 "
		. "-out $tdir/${type}_sm2.param "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate ${type} param: $!\n";

	system("$openssl req -config $tdir/$subca_cnf "
		. "-newkey ec:$tdir/${type}_sm2.param "
		. "-nodes -keyout $tdir/${type}_sign.key "
		. '-sm3 -sigopt sm2_id:1234567812345678 '
		. "-new -out $tdir/${type}_sign.csr "
		. "-subj /CN=${type}_sign "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate ${type} sign csr: $!\n";

	system("$openssl ca -batch -config $tdir/$subca_cnf "
		. "-in $tdir/${type}_sign.csr "
		. "-notext -out $tdir/${type}_sign.crt "
		. "-cert $tdir/$subca.crt -keyfile $tdir/$subca.key "
		. '-extensions sign_req -md sm3 '
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate ${type} sign crt $!\n";

	system("$openssl req -config $tdir/$subca_cnf "
		. "-newkey ec:$tdir/${type}_sm2.param "
		. "-nodes -keyout $tdir/${type}_enc.key "
		. '-sm3 -sigopt sm2_id:1234567812345678 '
		. "-new -out $tdir/${type}_enc.csr "
		. "-subj /CN=${type}_enc "
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate ${type} enc csr: $!\n";

	system("$openssl ca -batch -config $tdir/$subca_cnf "
		. "-in $tdir/${type}_enc.csr "
		. "-notext -out $tdir/${type}_enc.crt "
		. "-cert $tdir/$subca.crt -keyfile $tdir/$subca.key "
		. '-extensions enc_req -md sm3 '
		. ">>$tdir/openssl.out 2>&1") == 0
		or die "Can't generate ${type} enc crt $!\n";

	system("cat $tdir/${type}_subca.crt $tdir/${type}_ca.crt "
		. ">$tdir/${type}_ca_chain.crt");

	system("cat $tdir/${type}_sign.crt $tdir/${type}_enc.crt "
		. ">$tdir/${type}_sign_enc.crt");
}

###############################################################################
