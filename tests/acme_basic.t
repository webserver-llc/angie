#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME HTTP-01 challenge test

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use POSIX qw/ strftime /;
use Test::Deep qw/ cmp_deeply re /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::ACME;
use Test::Utils qw/ get_json /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require Date::Parse; };
plan(skip_all => 'Date::Parse not installed') if $@;

my $t = Test::Nginx->new()->has(qw/acme http_api http_ssl socket_ssl/)
	->has_daemon('openssl');

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 10053;

my $acme_helper = Test::Nginx::ACME->new({t => $t, dns_port => $dns_port});

my $pebble_port = port(14000);
my $http_port = port(5002);

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
        listen          127.0.0.1:8080;
        server_name     localhost;

        location /status/ {
            api /status/http/acme_clients/;
        }
    }

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

    acme_http_port $http_port;
}

EOF

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
	certificate_validity_period => 10
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(1);

subtest 'obtaining and renewing a certificate' => sub {
	my $expected_acme_clients = {
		test => {
			certificate => 'missing',
			details     => re(qr(.+)),
			state       => 'requesting'
		},
	};

	my $acme_clients = get_json('/status/');
	cmp_deeply($acme_clients, $expected_acme_clients, 'ACME clients API');

	my $cert_file = $t->testdir() . "/acme_client/test/certificate.pem";

	# First, obtain the certificate.

	my $obtained = 0;
	my $obtained_enddate = '';

	for (1 .. 480) {
		if (-s $cert_file) {
			$obtained_enddate
				= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

			next if $obtained_enddate eq '';

			chomp $obtained_enddate;

			my $s = strftime("%H:%M:%S GMT", gmtime());
			note("$0: obtained certificate on $s; enddate: $obtained_enddate");

			$obtained = 1;
			last;
		}

		select undef, undef, undef, 0.5;
	}

	ok($obtained, 'obtained certificate')
		or return 0;

	# Then try to use it.

	like(http_get('/', SSL => 1), qr/SECURED/, 'used certificate');

	# Finally, renew the certificate.

	my $renewed = 0;
	my $renewed_enddate = '';

	my $cert_details = 'The certificate was obtained on \w+ \w+\s+\d{1,2} '
		. '\d{1,2}\:\d{2}\:\d{2} 20\d{2}, the client is ready for renewal\.';

	$expected_acme_clients = {
		test => {
			certificate => 'valid',
			details     => re(qr/$cert_details/),
			state       => 'ready'
		}
	};

	for (1 .. 480) {
		select undef, undef, undef, 0.5;

		$renewed_enddate
			= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

		next if $renewed_enddate eq '';

		chomp $renewed_enddate;

		if ($renewed_enddate ne $obtained_enddate) {
			my $s = strftime("%H:%M:%S GMT", gmtime());
			note("$0: renewed certificate on $s; enddate: $renewed_enddate");

			$renewed = 1;

			$expected_acme_clients->{test}{next_run} =
				strftime('%Y-%m-%dT%H:%M:%SZ',
					gmtime(Date::Parse::str2time($renewed_enddate) - 5 // 0));

			last;
		}
	}

	ok($renewed, 'renewed certificate');

	cmp_deeply(get_json('/status/'), $expected_acme_clients, "API ok");
};

