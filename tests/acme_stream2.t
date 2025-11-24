#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Test for the ACME module in the stream context.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http_acme http_ssl socket_ssl/)
	->has(qw/stream stream_acme stream_ssl stream_return/);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen              %%PORT_9443%% ssl;
        server_name         1.example.com;

        # client not referenced, but variables used
        # acme                test1;

        ssl_certificate     \$acme_cert_test1;
        ssl_certificate_key \$acme_cert_key_test1;

        return              "HELLO FROM STREAM\n";
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    access_log %%TESTDIR%%/access.log;

    acme_client test1 https://localhost:14000/dir
        renew_before_expiry=0
        enabled=on
    ;

    acme_http_port %%PORT_5002%%;

    resolver 127.0.0.1:8053 ipv6=off;

    server {
        listen              %%PORT_8443%% ssl;
        server_name         2.example.com;

        acme                test1;

        ssl_certificate     \$acme_cert_test1;
        ssl_certificate_key \$acme_cert_key_test1;

        return 200 "HELLO\n";
    }
}

EOF

$t->create_certificate(
	cert    => 'certificate.pem',
	key     => 'private.key',
	dir     => 'acme_client/test1',
	domains => [qw/1.example.com 2.example.com/]
);

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(2);

is(get_server('1.example.com'), "HELLO FROM STREAM\n",
	'original certificate works as expected');

my $error_log = $t->read_file('error.log');

my $scheduled_for_renewal = 0;
my $ts = $1
	if $error_log =~ /
		\svalid\scertificate,\srenewal\sscheduled\s
		([[:alpha:]]+\s+[[:alpha:]]+\s+\d+\s+\d+\:\d+\:\d+\s+\d+),\s
		ACME\sclient:\stest1
	/x;

# TODO We could read the existing certificate's enddate and compare it with
# the logged date to be absolutely sure (Parse & openssl required).
# Do we need this?
$scheduled_for_renewal = defined $ts;

ok($scheduled_for_renewal, 'certificate scheduled for renewal as expected');

###############################################################################

sub get_server {
	my ($host) = @_;

	my $s = stream(
		PeerAddr => '127.0.0.1:' . port(9443),
		SSL => 1,
		SSL_hostname => $host
	);

	log_in("ssl sni: $host") if defined $host;

	return $s->read();
}

###############################################################################
