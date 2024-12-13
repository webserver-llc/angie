#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME DNS-01 challenge tests

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;
use IO::Socket::SSL;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'long test') unless $ENV{TEST_ANGIE_UNSAFE};
plan(skip_all => 'win32') if $^O eq 'MSWin32';
#plan(skip_all => 'must be root to listen on port 53') if $> != 0;

# This script requires pebble (see https://github.com/letsencrypt/pebble). If
# you build it from source, assume it lives in the directory below.
# Otherwise we expect it to be installed system-wide.
my $acme_server_dir = defined $ENV{PEBBLE_PATH} ? $ENV{PEBBLE_PATH}
                      : $ENV{HOME} . '/go/bin';

my $t = Test::Nginx->new()->has(qw/acme/);

my $d = $t->testdir();

my $pebble = "$acme_server_dir/pebble";

if (!-f $pebble) {
    $pebble = 'pebble';
    $t->has_daemon($pebble);
}

# XXX
my $dns_port = 11053;

my $http_port = port(5002);
my $tls_port = port(5001);
my $pebble_port = port(14000);
my $pebble_mgmt_port = port(15000);

my (@clients, @servers);

my @keys = (
    { type => 'rsa', bits => 2048 },
    { type => 'ecdsa', bits => 256 },
);

my @challenges = ('dns');

my $domain_count = 1;

# Each iteration creates 2 clients, one with the RSA key type, the other with
# the ECDSA. Each subsequent iteration also assigns a different challenge type.
for (1..2) {
    my $n = $_;

    my $chlg = $challenges[($n - 1) % @challenges];

    my $srv = {
        domains => [],
        clients => [],
    };

    for (1..2) {
        push(@{$srv->{domains}}, "angie-test${domain_count}.com");
        $domain_count++;
    }

    if ($chlg eq 'dns-01') {
        # The dns-01 validation method allows wildcard domain names.
        push(@{$srv->{domains}}, "*.angie-test${domain_count}.com");
        $domain_count++;
    }

    for my $key (@keys) {
        my $cli = {
            name => "test${n}_$key->{type}",
            key_type => $key->{type},
            key_bits => $key->{bits},
            challenge => $chlg,
            renewed => 0,
            enddate => "n/a",
        };

        push(@clients, $cli);
        push(@{$srv->{clients}}, $cli);
    }

    push(@servers, $srv);
}

my $conf_clients = "";
my $conf_servers = "";

my $account_key = "";
my $email = "";

for my $e (@clients) {
    $conf_clients .=  "    acme_client $e->{name} " .
        "https://127.0.0.1:$pebble_port/dir challenge=$e->{challenge} " .
        "key_type=$e->{key_type} key_bits=$e->{key_bits} $account_key $email;\n";

    # for a change...
    $email = ($email eq "" ) ? "email=admin\@angie-test.com" : "";
    $account_key = "account_key=$d/acme_client/$clients[0]->{name}/account.key";
}

for my $e (@servers) {

    $conf_servers .=
"    server {
#        listen       localhost:8080;  # XXX
        server_name  @{$e->{domains}};

";

    for my $cli (@{$e->{clients}}) {
        $conf_servers .= "        acme $cli->{name};\n";
    }

    $conf_servers .= "    }\n\n";
}

my $conf =
"
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # We don't need a resolver directive because we specify IPs
    # as ACME server addresses.
    #resolver localhost:$dns_port ipv6=off;

    acme_dns_port $dns_port;

$conf_servers
$conf_clients
}
";

$t->plan(scalar @clients);

$t->write_file_expand('nginx.conf', $conf);

pebble_start($t);

$t->run();

my $renewed_count = 0;
my $loop_start = time();

for (1 .. 20 * @clients) {

    for my $cli (@clients) {
        if (!$cli->{renewed}) {

            my $cert_file = "$d/acme_client/$cli->{name}/certificate.pem";

            if (-e $cert_file && -s $cert_file) {
                my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

                if ($s ne "") {
                    chomp($s);

                    $renewed_count++;
                    print("$0: $cli->{name} renewed certificate ($renewed_count of " .
                        @clients . ")\n");

                    $cli->{renewed} = 1;
                    $cli->{enddate} = $s;
                }
            }
        }
    }

    last if $renewed_count == @clients;

    if (!$renewed_count && time() - $loop_start > 20) {
        # If none of the clients has renewed during this time,
        # then there's probably no need to wait longer.
        print("$0: Quitting on timeout ...\n");
        last;
    }

    sleep(1);
}

for my $cli (@clients) {
    ok($cli->{renewed}, "$cli->{name} renewed certificate " .
        "(challenge: $cli->{challenge}; enddate: $cli->{enddate})");
}

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
    "certificateValidityPeriod": 157766400
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

    waitforsslsocket("0.0.0.0:$pebble_mgmt_port")
        or die("Couldn't start pebble");
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

