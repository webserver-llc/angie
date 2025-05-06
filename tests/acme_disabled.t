#!/usr/bin/perl

# (C) 2025 Web Server LLC

# tests for ACME clients being disabled in various ways (enabled=off, etc)

# This test verifies that the $acme_cert_* variables work correctly even when
# certificate renewal is disabled. We set up multiple ACME clients and disable
# them in various ways (e.g., enabled=off, etc.). For each client, we also
# create a certificate and private key, simulating a previous renewal. When we
# run this configuration, we expect the $acme_cert_* variables to provide
# access to the corresponding certificate and private key, even with ACME
# effectively disabled.

###############################################################################

use warnings;
use strict;

use File::Path qw/ make_path /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->has(qw/acme socket_ssl/);

my $d = $t->testdir();

my $client1 = 'test1';
my $client2 = 'test2';
my $client3 = 'test3';
my $client_dir1 = "$d/acme_client/$client1";
my $client_dir2 = "$d/acme_client/$client2";
my $client_dir3 = "$d/acme_client/$client3";

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # disabled
    acme_client $client1 https://localhost/dir enabled=off;
    # unused
    acme_client $client2 https://localhost/dir enabled=on;
    # invalid domain
    acme_client $client3 https://localhost/dir enabled=on;

    server {
        listen          127.0.0.1:8443 ssl;
        server_name     1.example.com;
        acme            $client1;

        ssl_certificate         \$acme_cert_test1;
        ssl_certificate_key     \$acme_cert_key_test1;

        location /a {
            return 200 "SECURED 1";
        }
    }

    server {
        listen          127.0.0.1:8543 ssl;
        server_name     2.example.com;

        ssl_certificate         \$acme_cert_test2;
        ssl_certificate_key     \$acme_cert_key_test2;

        location /b {
            return 200 "SECURED 2";
        }
    }

    server {
        listen          127.0.0.1:8643 ssl;
        # invalid domain for this case
        server_name     *.example.com;

        ssl_certificate         \$acme_cert_test3;
        ssl_certificate_key     \$acme_cert_key_test3;

        location /c {
            return 200 "SECURED 3";
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
prompt = no
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
x509_extensions = v3_req

[ req_distinguished_name ]
commonName=no.match.example.com

[ v3_req ]
subjectAltName = DNS:example.com,DNS:*.example.com
EOF

foreach my $dir ($client_dir1, $client_dir2, $client_dir3) {
	my $cert = "$dir/certificate.pem";
	my $cert_key = "$dir/private.key";

	make_path($dir);

	system('openssl req -x509 -new '
		. "-config $d/openssl.conf "
		. "-out $cert -keyout $cert_key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate $cert: $!\n";
}

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(3);

like(http_get('/a', SSL => 1, PeerAddr => '127.0.0.1:' . port(8443)),
	qr/SECURED 1/, 'client disabled but certificate accessible');
like(http_get('/b', SSL => 1, PeerAddr => '127.0.0.1:' . port(8543)),
	qr/SECURED 2/, 'client unused but certificate accessible');
like(http_get('/c', SSL => 1, PeerAddr => '127.0.0.1:' . port(8643)),
	qr/SECURED 3/, 'invalid domain but certificate accessible');
