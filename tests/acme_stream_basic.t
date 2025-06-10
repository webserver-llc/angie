#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Basic test for the ACME module in the stream context.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http_acme stream_acme socket_ssl stream_return/);

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 16053;

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

    acme_client test https://localhost:$pebble_port/dir;

    server {
        listen               %%PORT_8443%% ssl;
        server_name          angie-test1.com;

        ssl_certificate      \$acme_cert_test;
        ssl_certificate_key  \$acme_cert_key_test;

        acme                 test;

        location / {
            return           200 "\$server_name";
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

stream {
    %%TEST_GLOBALS_STREAM%%

    ssl_certificate          \$acme_cert_test;
    ssl_certificate_key      \$acme_cert_key_test;

    server {
        listen               127.0.0.1:%%PORT_8081%% ssl;

        server_name          angie-test2.com;

        acme                 test;

        return               \$server_name;
    }

    server {
        listen               127.0.0.1:%%PORT_8081%% ssl;

        server_name          angie-test3.com;

        acme                 test;

        return               \$server_name;
    }
}

EOF

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform', 1);

my $d = $t->testdir();

$t->plan(4);

my $obtained = 0;
my $http_server = 0;
my $stream_server1 = 0;
my $stream_server2 = 0;

my $cert_file = $t->testdir() . "/acme_client/test/certificate.pem";

# Wait for the certificate to arrive.

for (1 .. 20) {
	if (-s $cert_file) {
		$obtained = 1;
		last;
	}

	sleep 1;
}

# Try using it.

if ($obtained) {
	$http_server = http_content(http_get('/', SSL => 1)) eq "angie-test1.com";
	$stream_server1 = get_server("angie-test2.com") eq "angie-test2.com";
	$stream_server2 = get_server("angie-test3.com") eq "angie-test3.com";
}

ok($obtained, "certificate obtained");
ok($http_server, "http server");
ok($stream_server1, "stream server 1");
ok($stream_server2, "stream server 2");

###############################################################################

sub get_server {
	my ($host) = @_;

	my $s = stream(
		PeerAddr => '127.0.0.1:' . port(8081),
		SSL => 1,
		SSL_hostname => $host
	);

	log_in("ssl sni: $host") if defined $host;

	return $s->read();
}

###############################################################################
