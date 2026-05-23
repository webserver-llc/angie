#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Maxim Dounin
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, ssl_verify_depth.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl');

$t->plan(9)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    ssl_verify_client on;
    ssl_client_certificate root-int.crt;

    add_header X-Client $ssl_client_s_dn always;
    add_header X-Verify $ssl_client_verify always;

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;
        ssl_verify_depth 0;
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;
        ssl_verify_depth 1;
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;
        ssl_verify_depth 2;
    }
}

EOF

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
x509_extensions = myca_extensions
[ req_distinguished_name ]
[ myca_extensions ]
basicConstraints = critical,CA:TRUE
EOF

$t->write_file('ca.conf', <<EOF);
[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $d
database = $d/certindex
default_md = sha256
policy = myca_policy
serial = $d/certserial
default_days = 1
x509_extensions = myca_extensions

[ myca_policy ]
commonName = supplied

[ myca_extensions ]
basicConstraints = critical,CA:TRUE
EOF

foreach my $name ('root', 'localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

foreach my $name ('int', 'end') {
	system("openssl req -new "
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.csr -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('certserial', '1000');
$t->write_file('certindex', '');

system("openssl ca -batch -config $d/ca.conf "
	. "-keyfile $d/root.key -cert $d/root.crt "
	. "-subj /CN=int/ -in $d/int.csr -out $d/int.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign certificate for int: $!\n";

system("openssl ca -batch -config $d/ca.conf "
	. "-keyfile $d/int.key -cert $d/int.crt "
	. "-subj /CN=end/ -in $d/end.csr -out $d/end.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign certificate for end: $!\n";

$t->write_file('root-int.crt', $t->read_file('root.crt')
	. $t->read_file('int.crt'));

$t->write_file('t', '');
$t->run();

###############################################################################

# with verify depth 0, only self-signed certificates should
# be allowed

# OpenSSL 1.1.0+ instead limits the number of intermediate certs allowed;
# as a result, it is not possible to limit certificate checking
# to self-signed certificates only when using OpenSSL 1.1.0+

# LibreSSL 3.4.0+ interprets verify depth 0 as no limit

like(get(8080, 'root'), qr/SUCCESS/, 'verify depth 0 - root');

TODO: {
local $TODO = 'off-by-one depth in OpenSSL 1.1.0+'
	if $t->has_feature('openssl:1.1.0');
local $TODO = 'no zero depth in LibreSSL 3.4.0+'
	if $t->has_feature('libressl:3.4.0');

like(get(8080, 'int'),  qr/FAILED/, 'verify depth 0 - no int');

}

TODO: {
local $TODO = 'no zero depth in LibreSSL 3.4.0+'
	if $t->has_feature('libressl:3.4.0');

like(get(8080, 'end'),  qr/FAILED/,  'verify depth 0 - no end');

}

# with verify depth 1 (the default), one signature is
# expected to be checked, so certificates directly signed
# by the root cert are allowed, but nothing more

# OpenSSL 1.1.0+ instead limits the number of intermediate certs allowed;
# so with depth 1 it is possible to validate not only directly signed
# certificates, but also chains with one intermediate certificate

# LibreSSL 3.4.0+ ignores depth limit as long as verify callback returns 1;
# fixed in LibreSSL 4.3.0, broken again in master after LibreSSL 4.3.1
# (as seen on OpenBSD 7.9, with LibreSSL version reported as 4.3.0)

like(get(8081, 'root'), qr/SUCCESS/, 'verify depth 1 - root');
like(get(8081, 'int'),  qr/SUCCESS/, 'verify depth 1 - int');

TODO: {
local $TODO = 'off-by-one depth in OpenSSL 1.1.0+'
	if $t->has_feature('openssl:1.1.0');
local $TODO = 'ignored depth in LibreSSL 3.4.0+'
	if $t->has_feature('libressl:3.4.0')
	and not $t->has_feature('libressl:4.3.0')
	or $t->has_feature('libressl:4.3.0')
	and $^O eq 'openbsd'
	or $t->has_feature('libressl:4.3.1');

like(get(8081, 'end'),  qr/FAILED/, 'verify depth 1 - no end');

}

# with verify depth 2 it is also possible to validate up to two signatures,
# so chains with one intermediate certificate are allowed

like(get(8082, 'root'), qr/SUCCESS/, 'verify depth 2 - root');
like(get(8082, 'int'),  qr/SUCCESS/, 'verify depth 2 - int');
like(get(8082, 'end'),  qr/SUCCESS/, 'verify depth 2 - end');

###############################################################################

sub get {
	my ($port, $cert) = @_;
	http_get(
		"/t?$cert",
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_cert_file => "$d/$cert.crt",
		SSL_key_file => "$d/$cert.key"
	);
}

###############################################################################
