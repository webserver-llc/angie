package Test::Nginx::ACME;

# (C) 2025 Web Server LLC

# Utils for nginx ACME tests.

# TODO we need check that pebble and challtestsrv are ready to accept requests

###############################################################################

use warnings;
use strict;

use POSIX qw/ waitpid WNOHANG /;
use Test::More;

use Test::Control qw/stop_pid/;
use Test::Nginx qw/port/;

# This module requires pebble and pebble-challtestsrv (see
# https://github.com/letsencrypt/pebble). If you build them from source,
# assume they live in the directory below. Otherwise we expect them to be
# installed system-wide.
use constant ACME_SERVER_DIR => defined $ENV{PEBBLE_PATH}
	? $ENV{PEBBLE_PATH}
	: $ENV{HOME} . '/go/bin';

use constant PEBBLE_KEY => <<"EOF";
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

use constant PEBBLE_CERT => <<"EOF";
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

sub new {
	my ($class, $params) = @_;
	my $self = bless $params, $class;

	die 'No Test::Nginx instance passed to newly created ACME helper object'
		if !defined $self->{t} || ref $self->{t} ne 'Test::Nginx';

	$self->{dns_port} //= port(8053);

	return $self;
}

sub start_pebble {
	my ($self, $params) = @_;

	my $pebble = ACME_SERVER_DIR . '/pebble';
	if (!-f $pebble) {
		$pebble = 'pebble';
		$self->{t}->has_daemon($pebble);
	}

	# Create a leaf certificate and a private key for the Pebble HTTPS server.
	# Copied from
	# https://github.com/letsencrypt/pebble/tree/main/test/certs/localhost

	my $pebble_key = 'pebble-key.pem';
	$self->{t}->write_file($pebble_key, PEBBLE_KEY);

	my $pebble_cert = 'pebble-cert.pem';
	$self->{t}->write_file($pebble_cert, PEBBLE_CERT);

	my $mgmt_addr = defined $params->{mgmt_port}
		? '0.0.0.0:' . $params->{mgmt_port}
		: '';

	my $tls_port    = $params->{tls_port}    // port(5001);
	my $http_port   = $params->{http_port}   // port(5002);
	my $pebble_port = $params->{pebble_port} // port(14000);
	my $dns_port = defined $params->{dns_port}
		? $params->{dns_port}
		: $self->{dns_port};

	my $d = $self->{t}->testdir();

	# TODO pass the whole config?
	my $certificate_validity_period
		= $params->{certificate_validity_period} // 157766400;

	my $pebble_config = 'pebble-config.json';

	$self->{t}->write_file($pebble_config, <<"EOF");
{
  "pebble": {
    "listenAddress": "0.0.0.0:$pebble_port",
    "managementListenAddress": "$mgmt_addr",
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
    "certificateValidityPeriod": $certificate_validity_period
  }
}
EOF

	# Percentage of valid nonces that will be rejected by the server.
	# The default value is 5, and we don't want any of the nonces
	# to be rejected unless explicitly specified.
	$ENV{PEBBLE_WFE_NONCEREJECT} //= 0;

	$self->{t}->run_daemon($pebble,
		'-config', "$d/$pebble_config",
		'-dnsserver', '127.0.0.1:' . $dns_port
	);

	my $pid = $self->{t}{_daemons}[-1];
	$self->{t}{pebble} = $pid;

	if ($mgmt_addr) {
		unless ($self->{t}->waitforsslsocket($mgmt_addr)) {
			$self->stop_pebble();
			die "Couldn't start pebble's management interface on "
				. $mgmt_addr . ", pid $pid";
		}

		note("Pebble's management interface running on $mgmt_addr, pid $pid");
	}

	unless ($self->{t}->waitforsslsocket("0.0.0.0:$pebble_port")) {
		$self->stop_pebble();
		die "Couldn't start pebble on 0.0.0.0:$pebble_port, pid $pid";
	}

	note("Pebble running on 0.0.0.0:$pebble_port, pid $pid");
}

sub stop_pebble {
	my ($self) = @_;

	my $pid = $self->{t}{pebble};

	return unless $pid;

	my $exited;

	# Ctrl-C is the proper way to stop pebble
	kill 'INT', $pid;
	for (1 .. 900) {
		$exited = waitpid($pid, WNOHANG) != 0;
		last if $exited;
		select undef, undef, undef, 0.1;
	}

	stop_pid($pid, 1) unless $exited;
	undef $self->{t}{pebble};

	note("Pebble $pid stopped");
}

sub start_challtestsrv {
	my ($self, $params) = @_;

	my $challtestsrv = ACME_SERVER_DIR . '/pebble-challtestsrv';
	if (!-f $challtestsrv) {
		$challtestsrv = 'pebble-challtestsrv';
		$self->{t}->has_daemon($challtestsrv);
	}

	# TODO make me a constant? or global variable?
	my $mgmt_port = $params->{mgmt_port} // port(8055);
	my $http_port = defined $params->{http_port}
		? ':' . $params->{http_port}
		: '';
	my $dns_port = defined $params->{dns_port}
		? $params->{dns_port}
		: $self->{dns_port};

	my $d = $self->{t}->testdir();
	$self->{t}->run_daemon($challtestsrv,
		'-management', ":$mgmt_port",
		'-defaultIPv6', '',
		'-dns01', ":$dns_port",
		'-http01', $http_port,
		'-https01', '',
		'-doh', '',
		'-tlsalpn01', '',
	);

	my $pid = $self->{t}{_daemons}[-1];

	$self->{t}{challtestsrv} = $pid;

	unless ($self->{t}->waitforsocket("0.0.0.0:$mgmt_port")) {
		$self->stop_challtestsrv();
		die "Couldn't start challtestsrv's management interface on "
			. "0.0.0.0:$mgmt_port, pid $pid";
	}

	note("Challtestsrv's management interface running on 0.0.0.0:$mgmt_port, "
		. "pid $pid");

	unless ($self->{t}->waitforsocket("127.0.0.1:$dns_port")) {
		$self->stop_challtestsrv();
		die "Couldn't start challtestsrv's DNS server on "
			. "127.0.0.1:$dns_port, pid $pid";
	}

	note("Challtestsrv's DNS server running on 127.0.0.1:$dns_port, pid $pid");
}

sub stop_challtestsrv {
	my ($self) = @_;

	my $pid = $self->{t}{challtestsrv};

	return unless $pid;

	my $exited;

	# Ctrl-C is the proper way to stop challtestsrv
	kill 'INT', $pid;
	for (1 .. 900) {
		$exited = waitpid($pid, WNOHANG) != 0;
		last if $exited;
		select undef, undef, undef, 0.1;
	}

	stop_pid($pid, 1) unless $exited;
	undef $self->{t}{challtestsrv};

	note("Challtestsrv $pid stopped");
}

1;
