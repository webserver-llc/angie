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

my $t = Test::Nginx->new()->has(qw/acme http_ssl socket_ssl/)
	->has_daemon('openssl');

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 15053;

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
# expires. Then the script waits until Client 1 has renewed its certificate, and
# checks if Client 2 has scheduled its certificate for renewal as expected.

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
            return           200 "SECURED 1";
        }
    }

    server {
        listen               $ssl_port ssl;
        server_name          angie-$client2.com;

        ssl_certificate      \$acme_cert_$client2;
        ssl_certificate_key  \$acme_cert_key_$client2;

        acme                 $client2;

        location / {
            return           200 "SECURED 2";
        }
    }

    acme_http_port $http_port;
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

# We don't wait until the certificate expires, so we give it
# quite a long validity period.
my $enddate = strftime("%y%m%d%H%M%SZ", gmtime(time() + 60 * 60 * 24));

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
	. 'directives are not supported on this platform');

$t->plan(4);

# Before we start renewal, just check that the original
# certificate works fine.
like(get("angie-$client1.com"), qr/SECURED 1/,
	'original certificate works as expected');

my $renewed = 0;

for (1 .. 20) {
	if (!$renewed) {
		my $s = `openssl x509 -in $cert1 -issuer -noout`;

		if ($s =~ /^issuer.*pebble/i) {
			$renewed = time();
		}
	}

	last if $renewed;

	select undef, undef, undef, 1;
}

ok($renewed, "client1: certificate renewed");

$t->stop();

my $s = $t->read_file('acme.log');

my $renewed_on_load = 0;
if ($renewed) {
	$renewed_on_load = $s =~ /
		\svalid\scertificate,\s
		forced\srenewal\sscheduled\snow,\sACME\sclient:\stest1
	/x;
}

ok($renewed_on_load, "client1: certificate renewed on load");

my $scheduled_for_renewal = 0;
my $ts = $1
	if $s =~ /
		\svalid\scertificate,\srenewal\sscheduled\s
		([[:alpha:]]+\s+[[:alpha:]]+\s+\d+\s+\d+\:\d+\:\d+\s+\d+),\s
		ACME\sclient:\stest2
	/x;

my $t1 = Date::Parse::str2time($ts) // 0;

$ts = `openssl x509 -in $orig_cert -noout -enddate`;
$ts =~ s/notAfter=//;

chomp $ts;

my $t2 = Date::Parse::str2time($ts) // 0;

$scheduled_for_renewal = ($t1 != 0) && ($t1 == $t2);

ok($scheduled_for_renewal, "client2: certificate renews on " . $ts);

###############################################################################

sub get {
    my ($host) = @_;
    my $r = http(
        "GET / HTTP/1.0\nHost: $host\n\n",
        PeerAddr => '127.0.0.1:' . $ssl_port,
        SSL => 1,
        SSL_hostname => $host
    )
        or return "$@";
    return $r;
}

