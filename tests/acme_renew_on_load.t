#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME protocol support tests

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use File::Copy;
use File::Path qw/ make_path /;
use POSIX qw/ strftime /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require Date::Parse; };
plan(skip_all => 'Date::Parse not installed') if $@;

my $t = Test::Nginx->new()->has(qw/acme socket_ssl/);

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 20053;

my $acme_helper = Test::Nginx::ACME->new({t => $t, dns_port => $dns_port});

my $d = $t->testdir();

my $client1 = 'test1';
my $client2 = 'test2';
my $domain1 = "angie-$client1.com";
my $domain2 = "angie-$client2.com";

my $ssl_port = port(8443);
my $http_port = port(5002);
my $pebble_port = port(14000);

# This test creates a configuration with two servers. At the start, each server
# uses a copy of the same valid certificate. Also, each server has an ACME
# client to renew the certificate. Client 1 is configured to renew its
# certificate straight away and Client 2 to renew its certificate when it
# expires. Then the script waits until both certificates are renewed, and
# checks if they were renewed as configured.

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver localhost:$dns_port ipv6=off;

    acme_client $client1 https://localhost:$pebble_port/dir
                         renew_on_load
                         renew_before_expiry=0;

    acme_client $client2 https://localhost:$pebble_port/dir
                         renew_before_expiry=0;

    error_log acme.log notice;

    server {
        listen               $ssl_port ssl;
        server_name          angie-$client1.com;

        ssl_certificate      \$acme_cert_$client1;
        ssl_certificate_key  \$acme_cert_key_$client1;

        acme                 $client1;

        location / {
            return           200 "SECURED";
        }
    }

    server {
        listen               $ssl_port ssl;
        server_name          angie-$client2.com;

        ssl_certificate      \$acme_cert_$client2;
        ssl_certificate_key  \$acme_cert_key_$client2;

        acme                 $client2;

        location / {
            return           200 "SECURED";
        }
    }

    server {
        # XXX for http-01 validation with pebble.
        # it will send a validating HTTP request to this
        # port instead of 80; Angie will issue a warning though
        listen               $http_port;

        location / {
            return           200 "HELLO";
        }
    }
}

EOF

# Create the original certificate and copy it to the clients' directories.

my $cert_db = "cert_db";
my $cert_db_path = "$d/$cert_db";
my $cert_db_filename = "certs.db";
my $client_dir1 = "$d/acme_client/$client1";
my $client_dir2 = "$d/acme_client/$client2";
my $orig_cert = "$d/orig-certificate.pem";
my $orig_key = "$d/orig-private.key";
my $cert1 = "$client_dir1/certificate.pem";
my $cert_key1 = "$client_dir1/private.key";
my $cert2 = "$client_dir2/certificate.pem";
my $cert_key2 = "$client_dir2/private.key";

make_path($cert_db_path, $client_dir1, $client_dir2);
$t->write_file("$cert_db/$cert_db_filename", '');

$t->write_file('openssl.conf', <<EOF);
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = \@alt_names
[alt_names]
DNS.1 = $domain1
DNS.2 = $domain2
[ca]
default_ca = my_default_ca
[my_default_ca]
new_certs_dir = $cert_db_path
database      = $cert_db_path/$cert_db_filename
default_md    = default
rand_serial   = 1
policy        = my_ca_policy
copy_extensions = copy
email_in_dn   = no
default_days  = 365
[my_ca_policy]
EOF

# how long the original certificate lives before we renew it (sec)
my $orig_validity_time = 15;

my $enddate = strftime("%y%m%d%H%M%SZ", gmtime(time() + $orig_validity_time));

system("openssl genrsa -out $d/ca.key 4096 2>/dev/null") == 0
	&& system("openssl req -new -x509 -nodes -days 3650 "
		. "-subj '/CN=Original Test CA' -key $d/ca.key -out $d/ca.crt") == 0
	&& system("openssl req -new -nodes -out $d/csr.pem -newkey rsa:4096 "
		. "-keyout $orig_key -subj '/CN=Original Test CA' 2>/dev/null") == 0
	&& system("openssl ca -batch -notext -config $d/openssl.conf "
		. "-extensions v3_req -startdate 250101080000Z -enddate $enddate "
		. "-out $orig_cert -cert $d/ca.crt -keyfile $d/ca.key "
		. "-in $d/csr.pem 2>/dev/null") == 0
	|| die("Can't create the original certificate: $!");

copy($orig_cert, $cert1) && copy($orig_key, $cert_key1)
	&& copy($orig_cert, $cert2) && copy($orig_key, $cert_key2)
	|| die("Can't copy the original certificate/key: $!");

$acme_helper->start_challtestsrv();
$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
	certificate_validity_period => 120
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(4);

my ($renewed1, $renewed2) = (0, 0);

for (1 .. 30) {
	if (!$renewed1) {
		my $s = `openssl x509 -in $cert1 -issuer -noout`;

		if ($s =~ /^issuer.*pebble/i) {
			$renewed1 = time();
		}
	}

	if (!$renewed2) {
		my $s = `openssl x509 -in $cert2 -issuer -noout`;

		if ($s =~ /^issuer.*pebble/i) {
			$renewed2 = time();
		}
	}

	last if $renewed1 && $renewed2;

	sleep 1;
}

ok($renewed1, "client1: certificate renewed");
ok($renewed2, "client2: certificate renewed");

$t->stop();

my $s = $t->read_file('acme.log');

my $renewed_on_load = 0;
if ($renewed1) {
	$renewed_on_load = $s =~ /
		forced\srenewal\sof\scertificate,\s
		renewal\sscheduled\snow,\sACME\sclient:\stest1
	/x;
}
ok($renewed_on_load, "client1: certificate renewed on load");

my $renewed_as_scheduled = 0;
if ($renewed2) {
	my $ts = $1
		if $s =~ /
			valid\scertificate,\srenewal\sscheduled\s
			([[:alpha:]]+\s+[[:alpha:]]+\s+\d+\s+\d+\:\d+\:\d+\s+\d+),\s
			ACME\sclient:\stest2
		/x;

	my $t1 = Date::Parse::str2time($ts) // 0;

	$ts = `openssl x509 -in $orig_cert -noout -enddate`;
	$ts =~ s/notAfter=//;

	chomp $ts;

	my $t2 = Date::Parse::str2time($ts) // 0;

	$renewed_as_scheduled = ($t1 != 0) && ($t1 == $t2);
}
ok($renewed_as_scheduled, "client2: certificate renewed as scheduled");

