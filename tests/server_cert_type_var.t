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
	->has_daemon("$openssl")->plan(9);

my $is_old_openssl = ($t->has_module('OpenSSL')
	and not $t->has_feature('openssl:1.1.1'));
my $is_libressl = $t->has_module('LibreSSL');
my $is_boringssl = $t->has_module('BoringSSL');

if ($is_old_openssl or $is_libressl or $is_boringssl) {
	$t->write_file_expand('nginx.conf', <<'EOF');

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

} else {
	$t->write_file_expand('nginx.conf', <<'EOF');

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

}

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $tdir = $t->testdir();

my @types = ('rsa');

if (not ($is_old_openssl or $is_boringssl or $is_libressl)) {
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

system("$openssl ecparam -name secp384r1 -genkey -out $tdir/ecdsa.key "
		. ">> $tdir/openssl.out 2>&1") == 0
	or die "Can't create 'ecdsa' key$!\n";

system("$openssl req -new -config $tdir/openssl.conf "
	. "-subj /CN=ecdsa/ -key $tdir/ecdsa.key -x509 -nodes "
	. "-days 365 -out $tdir/ecdsa.crt "
	. ">> $tdir/openssl.out 2>&1") == 0
	or die "Can't create 'ecdsa' cecertificate: $!\n";

$t->run();

###############################################################################

like(https_get(8441), qr/RSA/, 'RSA certificate');
like(https_get(8442), qr/ECDSA/, 'ECDSA certificate');

SKIP: {
skip 'Elliptic curves and RSA-PSS are not supported in old OpenSSL', 3
	if $is_old_openssl;
skip 'Elliptic curves and RSA-PSS are not supported in LibreSSL', 3
	if $is_libressl;
skip 'Elliptic curves and RSA-PSS are not supported in BoringSSL', 3
	if $is_boringssl;

like(https_get(8443), qr/RSA-PSS/, 'RSA-PSS certificate');
like(https_get(8444), qr/ED448/, 'ED448 certificate');
like(https_get(8445), qr/ED25519/, 'ED25519 certificate');
}

TODO: {
# LibreSSL 3.9.2. To get a server certificate, use SSL_get_certificate().
# It returns the wrong certificate if multiple certificates are used in one
# server block. https://github.com/libressl/portable/issues/1059
local $TODO = 'Wrong server certificate in LibreSSL'
	if $is_libressl;
# https://trac.nginx.org/test/ticket/1375#no1
local $TODO = 'BoringSSL does not support dual certificates'
	if $is_boringssl;

like(https_cipher_get(8446, 'ECDHE-RSA-AES128-GCM-SHA256'),
	qr/RSA/, 'RSA certificate');
}

TODO: {
local $TODO = 'Wrong server certificate in older versions of LibreSSL'
	if $is_libressl and not $t->has_feature('libressl:4.0.0');

like(https_cipher_get(8446, 'ECDHE-ECDSA-AES128-SHA'),
	qr/ECDSA/, 'ECDSA certificate');
}

stream('127.0.0.1:' . port(8447))->io('test');

like(http_get('/', PeerAddr => '127.0.0.1:' . port(8448)),
	qr/-/, 'Empty variable');

$t->stop();

is($t->read_file('empty.log'), "-\n", 'Empty variable');

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
