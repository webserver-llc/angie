#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME protocol support tests

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

use POSIX qw/ strftime /;
use File::Path qw/ make_path /;
use File::Copy;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require Date::Parse; };
plan(skip_all => 'Date::Parse not installed') if $@;

# This script requires pebble and pebble-challtestsrv (see
# https://github.com/letsencrypt/pebble). If you build them from source,
# assume they live in the directory below. Otherwise we expect them to be
# installed system-wide.
my $acme_server_dir = defined $ENV{PEBBLE_PATH}
	? $ENV{PEBBLE_PATH}
	: $ENV{HOME} . '/go/bin';

my $t = Test::Nginx->new()->has(qw/acme socket_ssl/);

my $d = $t->testdir();

my $pebble = "$acme_server_dir/pebble";
my $challtestsrv = "$acme_server_dir/pebble-challtestsrv";

if (!-f $pebble) {
	$pebble = 'pebble';
	$t->has_daemon($pebble);
}

if (!-f $challtestsrv) {
	$challtestsrv = 'pebble-challtestsrv';
	$t->has_daemon($challtestsrv);
}

my $client1 = 'test1';
my $client2 = 'test2';
my $domain1 = "angie-$client1.com";
my $domain2 = "angie-$client2.com";

my $hook_port = port(9000);

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 20053;

my $ssl_port = port(8443);
my $http_port = port(5002);
my $tls_port = port(5001);
my $pebble_port = port(14000);
my $pebble_mgmt_port = port(15000);
my $challtestsrv_mgmt_port = port(8055);

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

    acme_client $client1 https://localhost:14000/dir
                         renew_on_load
                         renew_before_expiry=0;

    acme_client $client2 https://localhost:14000/dir
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

mkdir($cert_db_path);
$t->write_file("$cert_db/$cert_db_filename", '');

make_path($client_dir1);
make_path($client_dir2);

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

challtestsrv_start($t);
pebble_start($t);

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(4);

my $renewed1 = 0;
my $renewed2 = 0;
my $renewed_on_load = 0;
my $renewed_as_scheduled = 0;

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

$t->stop();

my $s = $t->read_file('acme.log');

if ($renewed1) {
	$renewed_on_load = $s =~ /
		forced\srenewal\sof\scertificate,\s
		renewal\sscheduled\snow,\sACME\sclient:\stest1
	/x;
}

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

ok($renewed1, "client1: certificate renewed");
ok($renewed_on_load, "client1: certificate renewed on load");
ok($renewed2, "client2: certificate renewed");
ok($renewed_as_scheduled, "client2: certificate renewed as scheduled");

###############################################################################

sub pebble_start {
	my ($t) = @_;

	my $pebble_key = 'pebble-key.pem';

	# Create a leaf certificate and a private key for the Pebble HTTPS server.
	# Copied from
	# https://github.com/letsencrypt/pebble/tree/main/test/certs/localhost

	$t->write_file($pebble_key, <<"EOF");
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmxTFtw113RK70H9pQmdKs9AxhFmnQ6BdDtp3jOZlWlUO0Blt
MXOUML5905etgtCbcC6RdKRtgSAiDfgx3VWiFMJH++4gUtnaB9SN8GhNSPBpFfSa
2JhWPo9HQNUsAZqlGTV4SzcGRqtWvdZxUiOfQ2TcvyXIqsaD19ivvqI1NhT6bl3t
redTZlzLLM6Wvkw6hfyHrJAPQP8LOlCIeDM4YIce6Gstv6qo9iCD4wJiY4u95HVL
7RK8t8JpZAb7VR+dPhbHEvVpjwuYd5Q05OZ280gFyrhbrKLbqst104GOQT4kQMJG
WxGONyTX6np0Dx6O5jU7dvYvjVVawbJwGuaL6wIDAQABAoIBAGW9W/S6lO+DIcoo
PHL+9sg+tq2gb5ZzN3nOI45BfI6lrMEjXTqLG9ZasovFP2TJ3J/dPTnrwZdr8Et/
357YViwORVFnKLeSCnMGpFPq6YEHj7mCrq+YSURjlRhYgbVPsi52oMOfhrOIJrEG
ZXPAwPRi0Ftqu1omQEqz8qA7JHOkjB2p0i2Xc/uOSJccCmUDMlksRYz8zFe8wHuD
XvUL2k23n2pBZ6wiez6Xjr0wUQ4ESI02x7PmYgA3aqF2Q6ECDwHhjVeQmAuypMF6
IaTjIJkWdZCW96pPaK1t+5nTNZ+Mg7tpJ/PRE4BkJvqcfHEOOl6wAE8gSk5uVApY
ZRKGmGkCgYEAzF9iRXYo7A/UphL11bR0gqxB6qnQl54iLhqS/E6CVNcmwJ2d9pF8
5HTfSo1/lOXT3hGV8gizN2S5RmWBrc9HBZ+dNrVo7FYeeBiHu+opbX1X/C1HC0m1
wJNsyoXeqD1OFc1WbDpHz5iv4IOXzYdOdKiYEcTv5JkqE7jomqBLQk8CgYEAwkG/
rnwr4ThUo/DG5oH+l0LVnHkrJY+BUSI33g3eQ3eM0MSbfJXGT7snh5puJW0oXP7Z
Gw88nK3Vnz2nTPesiwtO2OkUVgrIgWryIvKHaqrYnapZHuM+io30jbZOVaVTMR9c
X/7/d5/evwXuP7p2DIdZKQKKFgROm1XnhNqVgaUCgYBD/ogHbCR5RVsOVciMbRlG
UGEt3YmUp/vfMuAsKUKbT2mJM+dWHVlb+LZBa4pC06QFgfxNJi/aAhzSGvtmBEww
xsXbaceauZwxgJfIIUPfNZCMSdQVIVTi2Smcx6UofBz6i/Jw14MEwlvhamaa7qVf
kqflYYwelga1wRNCPopLaQKBgQCWsZqZKQqBNMm0Q9yIhN+TR+2d7QFjqeePoRPl
1qxNejhq25ojE607vNv1ff9kWUGuoqSZMUC76r6FQba/JoNbefI4otd7x/GzM9uS
8MHMJazU4okwROkHYwgLxxkNp6rZuJJYheB4VDTfyyH/ng5lubmY7rdgTQcNyZ5I
majRYQKBgAMKJ3RlII0qvAfNFZr4Y2bNIq+60Z+Qu2W5xokIHCFNly3W1XDDKGFe
CCPHSvQljinke3P9gPt2HVdXxcnku9VkTti+JygxuLkVg7E0/SWwrWfGsaMJs+84
fK+mTZay2d3v24r9WKEKwLykngYPyZw5+BdWU0E+xx5lGUd3U4gG
-----END RSA PRIVATE KEY-----
EOF

	my $pebble_cert = 'pebble-cert.pem';

	$t->write_file($pebble_cert, <<"EOF");
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIbEfayDFsBtwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMDcx
MjA2MTk0MjEwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCbFMW3DXXdErvQf2lCZ0qz0DGEWadDoF0O2neM5mVa
VQ7QGW0xc5Qwvn3Tl62C0JtwLpF0pG2BICIN+DHdVaIUwkf77iBS2doH1I3waE1I
8GkV9JrYmFY+j0dA1SwBmqUZNXhLNwZGq1a91nFSI59DZNy/JciqxoPX2K++ojU2
FPpuXe2t51NmXMsszpa+TDqF/IeskA9A/ws6UIh4Mzhghx7oay2/qqj2IIPjAmJj
i73kdUvtEry3wmlkBvtVH50+FscS9WmPC5h3lDTk5nbzSAXKuFusotuqy3XTgY5B
PiRAwkZbEY43JNfqenQPHo7mNTt29i+NVVrBsnAa5ovrAgMBAAGjYzBhMA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAiBgNVHREEGzAZgglsb2NhbGhvc3SCBnBlYmJsZYcEfwAAATANBgkq
hkiG9w0BAQsFAAOCAQEAYIkXff8H28KS0KyLHtbbSOGU4sujHHVwiVXSATACsNAE
D0Qa8hdtTQ6AUqA6/n8/u1tk0O4rPE/cTpsM3IJFX9S3rZMRsguBP7BSr1Lq/XAB
7JP/CNHt+Z9aKCKcg11wIX9/B9F7pyKM3TdKgOpqXGV6TMuLjg5PlYWI/07lVGFW
/mSJDRs8bSCFmbRtEqc4lpwlrpz+kTTnX6G7JDLfLWYw/xXVqwFfdengcDTHCc8K
wtgGq/Gu6vcoBxIO3jaca+OIkMfxxXmGrcNdseuUCa3RMZ8Qy03DqGu6Y6XQyK4B
W8zIG6H9SVKkAznM2yfYhW8v2ktcaZ95/OBHY97ZIw==
-----END CERTIFICATE-----
EOF

	my $pebble_config = 'pebble-config.json';

	$t->write_file($pebble_config, <<"EOF");
{
  "pebble": {
    "listenAddress": "0.0.0.0:$pebble_port",
    "managementListenAddress": "0.0.0.0:$pebble_mgmt_port",
    "certificate": "$d/$pebble_cert",
    "privateKey": "$d/$pebble_key",
    "httpPort": $http_port,
    "tlsPort": $tls_port,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked-domain.example"],
    "retryAfter": {
        "authz": 3,
        "order": 5
    },
    "certificateValidityPeriod": 120
  }
}
EOF

	# Percentage of valid nonces that will be rejected by the server.
	# The default value is 5, and we don't want any of the nonces to be rejected
	# unless explicitly specified.
	if (!defined $ENV{PEBBLE_WFE_NONCEREJECT}) {
		$ENV{PEBBLE_WFE_NONCEREJECT} = 0;
	}

	$t->run_daemon($pebble,
		'-config', "$d/$pebble_config",
		'-dnsserver', '127.0.0.1:' . $dns_port);

	$t->waitforsslsocket("0.0.0.0:$pebble_mgmt_port")
		or die("Couldn't start pebble");
}

###############################################################################

sub challtestsrv_start {
	my ($t) = @_;

	$t->run_daemon($challtestsrv,
		'-management', ":$challtestsrv_mgmt_port",
		'-defaultIPv6', "",
		'-dns01', ":$dns_port",
		'-http01', "",
		'-https01', "",
		'-doh', "",
		'-tlsalpn01', "",
	);

	$t->waitforsocket("0.0.0.0:$challtestsrv_mgmt_port")
		or die("Couldn't start challtestsrv");
}

###############################################################################

