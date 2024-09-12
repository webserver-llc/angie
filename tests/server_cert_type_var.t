#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for "ssl_server_cert_type" variable.

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

my $openssl = $ENV{'TEST_ANGIE_OPENSSL_BINARY'} || 'openssl';

my $t = Test::Nginx->new()
	->has(qw/http http_ssl/)
	->has_daemon("$openssl")->plan(9)
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

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8442 ssl;

        ssl_certificate_key ecdsa.key;
        ssl_certificate ecdsa.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8443 ssl;

        ssl_certificate_key rsa-pss.key;
        ssl_certificate rsa-pss.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8444 ssl;

        ssl_certificate_key ed448.key;
        ssl_certificate ed448.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8445 ssl;

        ssl_certificate_key ed25519.key;
        ssl_certificate ed25519.crt;

        location / {
            return 200 $ssl_server_cert_type;
        }
    }

    server {
        listen 127.0.0.1:8446 ssl;

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
        listen 127.0.0.1:8447 ssl;

        access_log %%TESTDIR%%/empty.log empty;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        location / {
            return 200;
        }
    }

    server {
        listen 127.0.0.1:8448;

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
	system("$openssl genpkey -algorithm $type -out $tdir/$type.key") == 0
		or die "Can't create '$type' key$!\n";

	system("$openssl req -new -config $tdir/openssl.conf "
		. "-subj /CN=$type/ -key $tdir/$type.key -x509 -nodes "
		. "-days 365 -out $tdir/$type.crt") == 0
		or die "Can't create '$type' cecertificate: $!\n";
}

system("$openssl ecparam -name secp384r1 -genkey -out $tdir/ecdsa.key") == 0
	or die "Can't create 'ecdsa' key$!\n";

system("$openssl req -new -config $tdir/openssl.conf "
	. "-subj /CN=ecdsa/ -key $tdir/ecdsa.key -x509 -nodes "
	. "-days 365 -out $tdir/ecdsa.crt") == 0
	or die "Can't create 'ecdsa' cecertificate: $!\n";

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
}

like(https_cipher_get(8446, 'ECDHE-RSA-AES128-GCM-SHA256'),
	qr/RSA/, 'RSA certificate');

like(https_cipher_get(8446, 'ECDHE-ECDSA-AES128-SHA'),
	qr/ECDSA/, 'ECDSA certificate');

my $s = stream('127.0.0.1:' . port(8447));

$s->io('test');

for (1 .. 50) {
	last if -s "$tdir/empty.log";
	select undef, undef, undef, 0.1;
}

is($t->read_file('empty.log'), "-\n", 'Empty variable');

like(http_get('/', PeerAddr => '127.0.0.1:' . port(8448)),
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

###############################################################################
