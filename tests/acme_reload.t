#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Testing the ACME client being disabled and then enabled.

# TODO: add a scenario with successful certificate issue?
#
###############################################################################

#!/usr/bin/perl

use warnings;
use strict;

use Test::Deep;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/ get_json $TIME_RE /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme http_api/)
	->skip_api_check()
	->plan(3);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver       127.0.0.53;

    acme_client    example https://127.0.0.1:8443/ enabled=off;
    acme_http_port 8000;

    server {
        listen          127.0.0.1:8000; # the same port as acme_http_port
        server_name     example.com;
        acme example;
    }

    server {
        listen          127.0.0.1:8080;
        server_name     localhost;

        location /status/ {
            api /status/http/acme_clients/;
        }
    }
}

EOF

$t->run();

my $expected_acme_clients = {
	example => {
		certificate => 'missing',
		details     => 'The client is disabled in the configuration.',
		state       => 'disabled'
	}
};

my $acme_clients = get_json('/status/');
cmp_deeply($acme_clients, $expected_acme_clients, 'disabled acme client')
	or diag(
		explain({got => $acme_clients, expected => $expected_acme_clients}));

# enable acme and reload
$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver       127.0.0.53;

    acme_client    example https://127.0.0.1:8443/;
    acme_http_port 8000;

    server {
        listen          127.0.0.1:8000;
        server_name     example.com;
        acme example;
    }

    server {
        listen          127.0.0.1:8080;
        server_name     localhost;

        location /status/ {
            api /status/http/acme_clients/;
        }
    }
}

EOF

SKIP: {
	skip 'reload is not working (perl >= 5.32 required)', 2
		unless $t->has_feature('reload');

	ok($t->reload(), 'reloaded');

	$expected_acme_clients = {
		example => {
			certificate => 'missing',
			details     =>
				'Certificate issuance has failed (see logs for more info).',
			state       => 'failed', # we couldn't connect to ACME server
			next_run    => $TIME_RE,
		}
	};

	$acme_clients = get_json('/status/');

	cmp_deeply($acme_clients, $expected_acme_clients,
		'enabled acme client, failed state')
			or diag(
				explain({
					got      => $acme_clients,
					expected => $expected_acme_clients
				})
			);
}
