#!/usr/bin/perl

# (C) 2025 Web Server LLC

# This test verifies that $acme_cert_key_* is empty, along with $acme_cert_*,
# when the certificate is unavailable.

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

my $t = Test::Nginx->new()->has(qw/acme socket_ssl/);
my $d = $t->testdir();

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 13053;

my $acme_helper = Test::Nginx::ACME->new({t => $t, dns_port => $dns_port});

my $pebble_port = port(14000);
my $http_port = port(5002);

$t->prepare_ssl();

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

    # We use a temporary certificate and key
    # until we obtain a proper certificate through ACME.

    map \$acme_cert_test \$cert_test {
        ''       $d/localhost.crt;
        default  \$acme_cert_test;
    }

    map \$acme_cert_key_test \$cert_key_test {
        ''       $d/localhost.key;
        default  \$acme_cert_key_test;
    }

    # Both \$cert and \$cert_key must contain 'EMPTY'
    # until we obtain a certificate.

    map \$acme_cert_test \$cert {
        ''       'EMPTY';
        default  'CERT';
    }

    map \$acme_cert_key_test \$cert_key {
        ''       'EMPTY';
        default  'KEY';
    }

    server {
        listen               %%PORT_8443%% ssl;
        server_name          angie-test1.com;

        ssl_certificate      \$cert_test;
        ssl_certificate_key  \$cert_key_test;

        acme                 test;

        location / {
            return           200 "\$cert_key \$cert";
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
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

$t->plan(2);

my ($obtained, $empty_key) = (0, 0);

for (1 .. 480) {
	my $s = http_content(http_get('/', SSL => 1));

	if (defined $s) {
		if (!$empty_key) {
			$empty_key = $s eq 'EMPTY EMPTY';
		}

		$obtained = $s eq 'KEY CERT';

		last if $obtained;
	}

	select undef, undef, undef, 0.5;
}

ok($empty_key, 'key empty without certificate');
ok($obtained, 'obtained certificate');
