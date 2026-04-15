#!/usr/bin/perl

# (C) 2026 Web Server LLC

# API tests for certificate information.

###############################################################################

use warnings;
use strict;

use Test::Deep qw/cmp_deeply ignore/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api http_ssl acme socket_ssl/)
	->has(qw/stream stream_acme stream_ssl/)
	->has_daemon('openssl');

my $d = $t->testdir();

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # All ACME clients are disabled, but certificates for two of them
    # are provided and will be listed in the acme_clients section.

    acme_client test1 https://localhost/ enabled=off;
    # "challenge=dns" is to allow wildcard domains
    acme_client test2 https://localhost/ challenge=dns enabled=off;
    # certificate missing
    acme_client test3 https://localhost/ enabled=off;

    server {
        listen 127.0.0.1:8080;

        location /status/ {
            api /;
        }
    }

    server {
        listen 127.0.0.1:8081 ssl;
        server_name 1.example.com 2.example.com;

        # 1
        ssl_certificate      '$d/chain1.pem';
        ssl_certificate_key  '$d/key1.pem';

        # reference ACME client to avoid warnings
        acme                 test1;

        location / {
            return 200;
        }
    }

    server {
        listen 127.0.0.1:8082 ssl;
        server_name *.example.com;

        # 2
        # same certificate/key used one more time
        # must be displayed only once
        ssl_certificate      '$d/chain1.pem';
        ssl_certificate_key  '$d/key1.pem';

        # reference ACME client to avoid warnings
        acme                 test2;

        location / {
            return 200;
        }
    }

    server {
        listen 127.0.0.1:8083 ssl;
        server_name 3.example.com 4.example.com;

        # 3
        # certificate/key specified via ACME variables
        # will not be displayed

        ssl_certificate      \$acme_cert_test2;
        ssl_certificate_key  \$acme_cert_key_test2;

        location / {
            return 200;
        }
    }
}

stream {
    # 4
    ssl_certificate      '$d/cert-s1.pem';
    ssl_certificate_key  '$d/key-s1.pem';

    server {

        server_name      s1.example.com;

        # reference ACME client to avoid warnings
        acme             test3;

        listen           127.0.0.1:8443 ssl;
    }

    server {
        # 5
        ssl_certificate      '$d/cert-s2.pem';
        ssl_certificate_key  '$d/key-s2.pem';

        listen           127.0.0.1:9443 ssl;
    }
}

EOF


# predictable start and end dates for certificates
# so we can verify them in a response
my $startdate = time();
my $enddate = $startdate + 60 * 60 * 24 * 30;

# Create certificate/key pairs to verify. RSA 4096 bit key type
# will be used by default.

# certificate/key for ACME client test1
$t->create_certificate(
	cert        => 'certificate.pem',
	key         => 'private.key',
	dir         => 'acme_client/test1',
	subj        => '/CN=ACME 1',
	name        => 'acme1',
	startdate   => $startdate,
	enddate     => $enddate,
	domains     => [qw/1.example.com 2.example.com/]
);

# certificate/key for ACME client test2
$t->create_certificate(
	cert        => 'certificate.pem',
	key         => 'private.key',
	dir         => 'acme_client/test2',
	subj        => '/CN=ACME 2',
	name        => 'acme2',
	startdate   => $startdate,
	enddate     => $enddate,
	domains     => [qw/*.example.com /]
);

# certificate/key to create a chain (1, 2)
$t->create_certificate(
	cert        => 'cert1.pem',
	key         => 'key1.pem',
	startdate   => $startdate,
	enddate     => $enddate,
	domains     => [qw/1.example.com 2.example.com/]
);

# certificate/key for the stream block (4)
$t->create_certificate(
	cert        => 'cert-s1.pem',
	key         => 'key-s1.pem',
	subj        => '/CN=stream 1',
	name        => 'stream1',
	startdate   => $startdate,
	enddate     => $enddate,
	domains     => [qw/ s1.example.com /]
);

# another certificate/key for the stream block (5)
$t->create_certificate(
	cert        => 'cert-s2.pem',
	key         => 'key-s2.pem',
	subj        => '/CN=stream 2',
	name        => 'stream2',
	startdate   => $startdate,
	enddate     => $enddate,
	domains     => [qw/ s2.example.com /]
);

# create a chain (1, 2)
system("cat $d/cert1.pem $d/default_ca.crt > $d/chain1.pem");

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(3 + 9);

my $api_resp = get_json("/status/");

my $expected_certificates_static = {
	# 1
	"$d/chain1.pem" => {
		"key" => "RSA (4096 bits)",
		"chain" => [
			{
				"subject" => {
					"alt_names" => [
						"1.example.com",
						"2.example.com"
					]
				},
				"issuer" => {
					"common_name" => "Angie Test CA"
				},
				"validity" => {
					"since" => gmtime_str($startdate),
					"until" => gmtime_str($enddate)
				}
			},
			{
				# at the moment, we cannot set the validity dates
				# for the root certificate, so we ignore them.
				"validity" => ignore(),
				"subject" => {
					"common_name" => "Angie Test CA"
				},
				"issuer" => {
					"common_name" => "Angie Test CA"
				}
			}
		]
	},
	# no 2, since certificate is the same as in 1
	# no 3, since certificate is specified via ACME variables
	# 4
	"$d/cert-s1.pem" => {
		"key" => "RSA (4096 bits)",
		"chain" => [
			{
				"issuer" => {
					"common_name" => "stream 1"
				},
				"subject" => {
					"alt_names" => [
						"s1.example.com"
					]
				},
				"validity" => {
					"since" => gmtime_str($startdate),
					"until" => gmtime_str($enddate)
				}
			}
		]
	},
	# 5
	"$d/cert-s2.pem" => {
		"key" => "RSA (4096 bits)",
		"chain" => [
			{
				"subject" => {
					"alt_names" => [
						"s2.example.com"
					]
				},
				"issuer" => {
					"common_name" => "stream 2"
				},
				"validity" => {
					"since" => gmtime_str($startdate),
					"until" => gmtime_str($enddate)
				}
			}
		]
	}
};

my $expected_certificates_acme_clients = {
	"test1" => {
		"key" => "RSA (4096 bits)",
		"chain" => [
			{
				"validity" => {
					"since" => gmtime_str($startdate),
					"until" => gmtime_str($enddate)
				},
				"subject" => {
					"alt_names" => [
						"1.example.com",
						"2.example.com"
					]
				},
				"issuer" => {
					"common_name" => "ACME 1"
				}
			}
		]
	},
	"test2" => {
		"key" => "RSA (4096 bits)",
		"chain" => [
			{
				"subject" => {
					"alt_names" => [
						"*.example.com"
					]
				},
				"validity" => {
					"since" => gmtime_str($startdate),
					"until" => gmtime_str($enddate)
				},
				"issuer" => {
					"common_name" => "ACME 2"
				}
			}
		]
	}
	# no "test3", since client has no certificate
};

my $expected_acme_clients = {
	"test1" => {
		"state" => "disabled",
		"certificate" => "valid",
		"details" => "The client is disabled in the configuration."
	},
	"test2" => {
		"state" => "disabled",
		"certificate" => "valid",
		"details" => "The client is disabled in the configuration."
	},
	"test3" => {
		"state" => "disabled",
		"certificate" => "missing",
		"details" => "The client is disabled in the configuration."
	}
};

cmp_deeply($api_resp->{certificates}{static},
	$expected_certificates_static,
	'static certificates');

cmp_deeply($api_resp->{certificates}{acme_clients},
	$expected_certificates_acme_clients,
	'acme clients certificates');

cmp_deeply($api_resp->{status}{http}{acme_clients},
	$expected_acme_clients,
	'acme clients');

my %queries = (
	"/status/certificates/acme_clients/test1"
		=> $api_resp->{certificates}{acme_clients}{test1},

	"/status/certificates/acme_clients/non_existent"
		# non-existent field
		=> {
			"description" => "Requested API entity \"/certificates/"
							."acme_clients/non_existent\" doesn't exist.",
			"error" => "PathNotFound"
		},

	"/status/certificates/acme_clients/test1/chain/0/issuer/common_name"
		=> "ACME 1",

	"/status/certificates/acme_clients/test1/chain/0/validity/until"
		=> gmtime_str($enddate),

	"/status/certificates/acme_clients/test1/chain/0/subject/alt_names/1"
		=> "2.example.com",

	"/status/certificates/acme_clients/test1/chain/0/subject/alt_names/1/xxx"
		# non-existent field
		=> {
			"error" => "PathNotFound",
			"description" => "Requested API entity \"/certificates/"
							. "acme_clients/test1/chain/0/subject/alt_names/"
							. "1/xxx\" doesn't exist."
		},

	"/status/certificates/acme_clients/test1/chain/0/subject/alt_names/3"
		# out-of-range element
		=> {
			"error" => "PathNotFound",
			"description" => "Requested API entity \"/certificates/"
							. "acme_clients/test1/chain/0/subject/"
							. "alt_names/3\" doesn't exist.",
		},

	"/status/status/http/acme_clients/test1/state"
		=> "disabled",

	"/status/status/http/acme_clients/test3/certificate"
		=> "missing",
);


while (my ($path, $expected) = each %queries) {
	$api_resp = get_json($path);

	cmp_deeply($api_resp, $expected, "GET $path handled correctly");
}

###############################################################################

# Converts time to the OpenSSL string format used in "validity" fields.
sub gmtime_str {
	my ($time) = @_;
	my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	my ($sec, $min, $hour, $mday, $mon, $year) = (gmtime($time))[0..5];

	return sprintf("%s %2d %02d:%02d:%02d %d GMT",
		$mon[$mon], $mday, $hour, $min, $sec, $year + 1900);
}

###############################################################################

