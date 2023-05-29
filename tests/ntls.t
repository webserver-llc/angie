#!/usr/bin/perl

# (C) Web-Server LLC

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use IPC::Open3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $openssl = $ENV{'TEST_ANGIE_OPENSSL_BINARY'} || 'openssl';

my $t = Test::Nginx->new()->has(qw/ntls http http_ssl/)
	->has_daemon($openssl);

plan(skip_all => 'no NTLS client')
	if `$openssl s_client -help 2>&1` !~ /-ntls/m;

$t->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen  127.0.0.1:%%PORT_8080%%;
        listen  127.0.0.1:%%PORT_8081%% ssl;

        ssl_certificate_key rsa.key;
        ssl_certificate     rsa.crt;

        ssl_certificate_key ec.key;
        ssl_certificate     ec.crt;

        ssl_ntls  on;
        ssl_certificate        server_sign.crt server_enc.crt;
        ssl_certificate_key    server_sign.key server_enc.key;

        ssl_trusted_certificate     client_ca_chain.crt;

        location / {
            return 200 "proto=$ssl_protocol,cipher=$ssl_cipher";
        }

        location /proxy {
            proxy_ssl_ntls on;

            proxy_ssl_certificate        client_sign.crt client_enc.crt;
            proxy_ssl_certificate_key    client_sign.key client_enc.key;

            proxy_ssl_trusted_certificate     server_ca_chain.crt;


            proxy_ssl_ciphers "ECC-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-SM3:RSA";

            proxy_pass https://127.0.0.1:%%PORT_8081%%/;
        }
    }
}

EOF

my $d = $t->testdir();

gen_rsa_and_ec($t);
gen_sm2($t, "client");
gen_sm2($t, "server");

$t->run();

like(ntls_get('-cipher ECC-SM2-SM4-CBC-SM3 -enable_ntls -ntls'),
	qr/^proto=NTLSv(\d|\.)+,cipher=ECC-SM2-SM4-CBC-SM3$/m,
	'NTLS on, ECC-SM2-SM4-CBC-SM3');

like(ntls_get('-cipher ECC-SM2-SM4-GCM-SM3 -enable_ntls -ntls'),
	qr/^proto=NTLSv(\d|\.)+,cipher=ECC-SM2-SM4-GCM-SM3$/m,
	'NTLS on, ECC-SM2-SM4-GCM-SM3');

like(ntls_get('-cipher ECDHE-SM2-SM4-CBC-SM3 '
		. "-enc_cert $d/client_enc.crt -enc_key $d/client_enc.key "
		. "-sign_cert $d/client_sign.crt -sign_key $d/client_sign.key "
		. '-enable_ntls -ntls'),
	qr/^proto=NTLSv(\d|\.)+,cipher=ECDHE-SM2-SM4-CBC-SM3$/m,
	'NTLS on, ECDHE-SM2-SM4-CBC-SM3');

like(ntls_get('-cipher ECDHE-SM2-SM4-GCM-SM3 '
		. "-enc_cert $d/client_enc.crt -enc_key $d/client_enc.key "
		. "-sign_cert $d/client_sign.crt -sign_key $d/client_sign.key "
		. '-enable_ntls -ntls'),
	qr/^proto=NTLSv(\d|\.)+,cipher=ECDHE-SM2-SM4-GCM-SM3$/m,
	'NTLS on, ECDHE-SM2-SM4-GCM-SM3');

like(ntls_get('-cipher aRSA'), qr/^proto=TLSv(\d|\.)+,/m, 'NTLS on, RSA');

like(ntls_get('-cipher aECDSA'), qr/^proto=TLSv(\d|\.)+,/m, 'NTLS on, ECDSA');


like(http_get('/proxy'), qr/^proto=NTLSv(\d|\.)+,cipher=ECC-SM2-SM4-CBC-SM3$/m,
	'NTLS proxy, ECC-SM2-SM4-CBC-SM3');


###############################################################################

sub ntls_get {
	my ($args) = @_;
	my $r;

	my $p = port(8081);

	my $pid = open3(my $ssl_in, my $ssl_out, my $ssl_err,
		"$openssl s_client -connect localhost:$p -quiet -ign_eof " . $args)
    or die "Can't run $openssl: $!";

	print $ssl_in "GET / HTTP/1.0\r\n\r\n" ;
	while (<$ssl_out>) { $r .= $_ }

	waitpid($pid, 0);

	return $r;
}

sub gen_rsa_and_ec {
    my ($t) = @_;

	$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

	system("$openssl genrsa -out $d/rsa.key 1024 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate RSA pem: $!\n";

	system("$openssl req -x509 -new -key $d/rsa.key "
		. "-config $d/openssl.conf -subj /CN=rsa/ "
		. "-out $d/rsa.crt -keyout $d/rsa.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate cert for RSA: $!\n";

	system("$openssl ecparam -genkey -out $d/ec.key -name prime256v1 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create EC pem: $!\n";

	system("$openssl req -x509 -new -key $d/ec.key "
		. "-config $d/openssl.conf -subj /CN=ec/ "
		. "-out $d/ec.crt -keyout $d/ec.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate cert for EC: $!\n";
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
new_certs_dir = $d/$ca/newcerts
database = $d/$ca/certindex
serial = $d/$ca/certserial
default_days = 3

# The root key and root certificate.
private_key = $d/$ca/ca.key
certificate = $d/$ca/ca.crt

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

	mkdir("$d/$ca");
	mkdir("$d/$ca/newcerts");

	$t->write_file("$ca/certserial", '1000');
	$t->write_file("$ca/certindex", '');

	system("$openssl ecparam -genkey -name SM2 "
		. "-out $d/$ca.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate CA key: $!\n";

	system("$openssl req -config $d/$ca_cnf "
		. "-new -key $d/$ca.key "
		. "-out $d/$ca.csr "
		. '-sm3 -nodes -sigopt sm2_id:1234567812345678 '
		. "-subj /CN=${type}_root_ca "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate CA csr: $!\n";

	system("$openssl ca -batch -selfsign "
		. "-config $d/$ca_cnf "
		. "-in $d/$ca.csr -keyfile $d/$ca.key "
		. '-extensions v3_ca -notext -md sm3 '
		. "-out $d/$ca.crt "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate CA crt: $!\n";


	$t->write_file($subca_cnf, <<EOF);
[ ca ]
default_ca = mysubca

[ mysubca ]
new_certs_dir = $d/$subca/newcerts
database = $d/$subca/certindex
serial = $d/$subca/certserial
default_days = 3
unique_subject = no

# The root key and root certificate.
private_key = $d/$subca/subca.key
certificate = $d/$subca/subca.crt

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

	mkdir("$d/$subca");
	mkdir("$d/$subca/newcerts");

	$t->write_file("$subca/certserial", '1000');
	$t->write_file("$subca/certindex", '');

	system("$openssl ecparam -genkey -name SM2 "
		. "-out $d/$subca.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't genearate sub CA key: $!\n";

	system("$openssl req -config $d/$ca_cnf "
		. "-new -key $d/$subca.key "
		. "-out $d/$subca.csr "
		. '-sm3 -nodes -sigopt sm2_id:1234567812345678 '
		. "-subj /CN=${type}_sub_ca "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate sub CA csr: $!\n";

	system("$openssl ca -batch "
		. "-config $d/$ca_cnf "
		. "-in $d/$subca.csr "
		. "-cert $d/$ca.crt -keyfile $d/$ca.key "
		. '-extensions v3_intermediate_ca -notext -md sm3 '
		. "-out $d/$subca.crt "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate sub CA crt: $!\n";


	system("$openssl ecparam -name SM2 "
		. "-out $d/${type}_sm2.param "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate ${type} param: $!\n";

	system("$openssl req -config $d/$subca_cnf "
		. "-newkey ec:$d/${type}_sm2.param "
		. "-nodes -keyout $d/${type}_sign.key "
		. '-sm3 -sigopt sm2_id:1234567812345678 '
		. "-new -out $d/${type}_sign.csr "
		. "-subj /CN=${type}_sign "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate ${type} sign csr: $!\n";

	system("$openssl ca -batch -config $d/$subca_cnf "
		. "-in $d/${type}_sign.csr "
		. "-notext -out $d/${type}_sign.crt "
		. "-cert $d/$subca.crt -keyfile $d/$subca.key "
		. '-extensions sign_req -md sm3 '
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate ${type} sign crt $!\n";

	system("$openssl req -config $d/$subca_cnf "
		. "-newkey ec:$d/${type}_sm2.param "
		. "-nodes -keyout $d/${type}_enc.key "
		. '-sm3 -sigopt sm2_id:1234567812345678 '
		. "-new -out $d/${type}_enc.csr "
		. "-subj /CN=${type}_enc "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate ${type} enc csr: $!\n";

	system("$openssl ca -batch -config $d/$subca_cnf "
		. "-in $d/${type}_enc.csr "
		. "-notext -out $d/${type}_enc.crt "
		. "-cert $d/$subca.crt -keyfile $d/$subca.key "
		. '-extensions enc_req -md sm3 '
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate ${type} enc crt $!\n";


	system("cat $d/${type}_subca.crt $d/${type}_ca.crt "
		. ">$d/${type}_ca_chain.crt");

	system("cat $d/${type}_sign.crt $d/${type}_enc.crt "
		. ">$d/${type}_sign_enc.crt");
}
