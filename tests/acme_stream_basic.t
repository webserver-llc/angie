#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Basic test for the ACME module in the stream context.

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
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;
use Test::Nginx::ACME;
use Test::Utils qw/ get_json /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require Date::Parse; };
plan(skip_all => 'Date::Parse not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http_acme http_api http_ssl socket_ssl/)
	->has(qw/stream stream_acme stream_ssl stream_return/);

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
        listen          127.0.0.1:8080;
        server_name     localhost;

        location /status/ {
            api /status/http/acme_clients/;
        }
    }

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

    acme_http_port           $http_port;
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
	. 'directives are not supported on this platform');

$t->plan(4 + 2);

my $expected_acme_clients = {
	test => {
		certificate => 'missing',
		details     => re(qr/\.+/),
		state       => 'requesting'
	},
};
cmp_deeply(get_json('/status/'), $expected_acme_clients, 'ACME API - initial');

my $cert_file = $t->testdir() . "/acme_client/test/certificate.pem";

# Wait for the certificate to arrive.

my $obtained = 0;
my $next_run;
for (1 .. 20) {
	if (-s $cert_file) {
		$obtained = 1;

		my $obtained_enddate
			= `openssl x509 -in $cert_file -enddate -noout | cut -d= -f 2`;

		chomp $obtained_enddate;

		# renew_before_expiry = 30d by default
		# 30d = 30 * 24 * 60 * 60 = 2592000s
		$next_run = strftime('%Y-%m-%dT%H:%M:%SZ',
			gmtime(Date::Parse::str2time($obtained_enddate) - 2592000 // 0));

		last;
	}

	sleep 1;
}

ok($obtained, "certificate obtained");

my $cert_details = 'The certificate was obtained on \w+ \w+ \d{1,2} '
	. '\d{1,2}\:\d{2}\:\d{2} 20\d{2}, the client is ready for renewal\.';

$expected_acme_clients = {
	test => {
		certificate => 'valid',
		details     => re(qr/$cert_details/),
		next_run    => $next_run,
		state       => 'ready'
	}
};

cmp_deeply(get_json('/status/'), $expected_acme_clients,
	'ACME API - obtained');

# Try using it.

is(http_content(http_get('/', SSL => 1)), 'angie-test1.com', 'http server');
is(get_server('angie-test2.com'), 'angie-test2.com', 'stream server 1');
is(get_server('angie-test3.com'), 'angie-test3.com', 'stream server 2');

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
