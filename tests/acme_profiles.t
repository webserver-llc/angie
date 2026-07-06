#!/usr/bin/perl

# (C) 2026 Web Server LLC

# ACME profiles test

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Time::Local qw(timegm);
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme http_api http_ssl socket_ssl/);

my $acme_helper = Test::Nginx::ACME->new({t => $t});

plan(skip_all => 'acme profiles not supported by server')
	unless $acme_helper->{_profiles_supported};

my $pebble_port = port(14000);
my $http_port = port(5002);

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	http_port => $http_port,
	profiles => {
		test => {
			description => 'A test profile',
		}
	}
});

# Test handling of profile misconfiguration.

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_log acme.log debug;

    acme_client test https://127.0.0.1:$pebble_port/dir
                email=admin\@example.com
                # There was no such profile in the pebble
                # configuration, so we should get an error
                # message.
                profile=nonexistent;

    server {
        server_name  example.com;

        acme         test;
    }

    acme_http_port   $http_port;
}

EOF

$t->run();

$t->plan(1);

select undef, undef, undef, 0.5;

$t->stop();

my $log = $t->read_file('acme.log');

my $wrong_profile
	= $log =~ /ACME\sserver\sdoes\snot\ssupport\sprofile\s"nonexistent",
				\ssupported\sprofiles:\s"test"/x;

ok($wrong_profile, 'profile misconfiguration handled');
