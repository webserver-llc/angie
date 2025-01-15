#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME HTTP-01 challenge test

###############################################################################

use warnings;
use strict;

use IO::Socket::SSL;
use POSIX qw/ strftime /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# This script requires pebble and pebble-challtestsrv (see
# https://github.com/letsencrypt/pebble). If you build them from source,
# assume they live in the directory below. Otherwise we expect them to be
# installed system-wide.
my $acme_server_dir = defined $ENV{PEBBLE_PATH}
	? $ENV{PEBBLE_PATH}
	: $ENV{HOME} . '/go/bin';

my $t = Test::Nginx->new()->has(qw/acme/);

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

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 20053;

my $http_port = port(5002);
my $tls_port = port(5001);
my $pebble_port = port(14000);
my $pebble_mgmt_port = port(15000);
my $challtestsrv_mgmt_port = port(8055);

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver localhost:$dns_port ipv6=off;

    acme_client test https://localhost:$pebble_port/dir
                email=admin\@angie-test.com;

    server {
        listen               %%PORT_8443%% ssl;
        server_name          angie-test900.com
                             angie-test901.com
                             angie-test902.com;

        ssl_certificate      \$acme_cert_test;
        ssl_certificate_key  \$acme_cert_key_test;

        acme                 test;

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

challtestsrv_start($t);
pebble_start($t);

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(1);

subtest 'obtaining and renewing a certificate' => sub {
	my $cert_file = "$d/acme_client/test/certificate.pem";

	# First, obtain the certificate.

	my $obtained = 0;
	my $obtained_enddate = '';

	for (1 .. 30) {
		if (-e $cert_file && -s $cert_file) {
			$obtained_enddate
				= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

			if ($obtained_enddate ne '') {
				chomp $obtained_enddate;

				my $s = strftime("%H:%M:%S GMT", gmtime());
				note("$0: obtained certificate on $s; "
					. "enddate: $obtained_enddate\n");

				$obtained = 1;
				last;
			}
		}

		sleep 1;
	}

	ok($obtained, 'obtained certificate')
		or return 0;

	# Then try to use it.

	like(http_get('/', SSL => 1), qr/SECURED/, 'used certificate');

	# Finally, renew the certificate.

	my $renewed = 0;
	my $renewed_enddate = '';

	for (1 .. 40) {
		sleep 1;

		$renewed_enddate
			= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

		next if $renewed_enddate eq '';

		chomp $renewed_enddate;

		if ($renewed_enddate ne $obtained_enddate) {
			my $s = strftime("%H:%M:%S GMT", gmtime());
			note("$0: renewed certificate on $s; enddate: $renewed_enddate\n");

			$renewed = 1;
			last;
		}
	}

	ok($renewed, 'renewed certificate');
};

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
    "certificateValidityPeriod": 10
  }
}
EOF

	# Percentage of valid nonces that will be rejected by the server.
	# The default value is 5, and we don't want any of the nonces
	# to be rejected unless explicitly specified.
	if (!defined $ENV{PEBBLE_WFE_NONCEREJECT}) {
		$ENV{PEBBLE_WFE_NONCEREJECT} = 0;
	}

	$t->run_daemon($pebble,
		'-config', "$d/$pebble_config",
		'-dnsserver', '127.0.0.1:' . $dns_port);

	waitforsslsocket("0.0.0.0:$pebble_mgmt_port")
		or die("Couldn't start pebble");
}

###############################################################################

sub challtestsrv_start {
	my ($t) = @_;

	$t->run_daemon($challtestsrv,
		'-management', ":$challtestsrv_mgmt_port",
		'-defaultIPv6', '',
		'-dns01', ":$dns_port",
		'-http01', '',
		'-https01', '',
		'-doh', '',
		'-tlsalpn01', '',
	);

	$t->waitforsocket("0.0.0.0:$challtestsrv_mgmt_port")
		or die("Couldn't start challtestsrv");
}

###############################################################################

sub waitforsslsocket {
	my ($peer) = @_;

	# analogously to Nginx::waitforsocket()

	for (1 .. 50) {
		my $s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => $peer,
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE()
		);

		return 1 if defined $s;

		select undef, undef, undef, 0.1;
	}

	return undef;
}

