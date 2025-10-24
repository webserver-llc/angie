#!/usr/bin/perl

# (C) 2025 Web Server LLC

# The test verifies that requests sent to a socket dedicated exclusively
# to ACME challenges are handled correctly.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use POSIX qw/ strftime /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme http_ssl socket_ssl/)
	->has_daemon('openssl');

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 17553;

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

    acme_http_port 127.0.0.1:$http_port;

    server {
        listen *:$http_port;
        return 200 '\$request_uri';
    }

}

EOF

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(2);

my $cert_file = $t->testdir() . "/acme_client/test/certificate.pem";

my $obtained = 0;
my $expected = -1;
my $obtained_enddate = '';
my $count = 1;
my $octet = 1;

my $loop_start = time();

for (;;) {
	if (-s $cert_file) {
		$obtained_enddate
			= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

		next if $obtained_enddate eq '';

		chomp $obtained_enddate;

		my $s = strftime("%H:%M:%S GMT", gmtime());
		note("$0: obtained certificate on $s; enddate: $obtained_enddate");

		$obtained = 1;
	}

	if ($expected) {
		# These requests should be accepted because they are sent to addresses
		# matching a wildcard specified in a server block.

		my $s = http_content(
			http_get("/$count", PeerAddr => "127.0.0.$octet:" . $http_port));

		$expected = ($s eq "/$count");

		$count++;

		$octet++;
		$octet = 1 if $octet > 2;
	}

	last if $obtained || (time() - $loop_start > 30);
}

ok($obtained, 'obtained certificate');

$expected = ($expected > 0);

ok($expected, 'handled all unexpected requests');

