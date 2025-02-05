#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME HTTP-01 challenge test

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use POSIX qw/ strftime /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

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

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
	certificate_validity_period => 10
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(1);

subtest 'obtaining and renewing a certificate' => sub {
	my $cert_file = $t->testdir() . "/acme_client/test/certificate.pem";

	# First, obtain the certificate.

	my $obtained = 0;
	my $obtained_enddate = '';

	for (1 .. 30) {
		if (-e $cert_file && -s $cert_file) {
			$obtained_enddate
				= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

			next if $obtained_enddate eq '';

			chomp $obtained_enddate;

			my $s = strftime("%H:%M:%S GMT", gmtime());
			note("$0: obtained certificate on $s; enddate: $obtained_enddate");

			$obtained = 1;
			last;
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
			note("$0: renewed certificate on $s; enddate: $renewed_enddate");

			$renewed = 1;
			last;
		}
	}

	ok($renewed, 'renewed certificate');
};

