#!/usr/bin/perl

# (C) 2025 Web Server LLC

# ACME tests for handling invalid domain names in the server_name directive

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme/)->plan(5);

# config 1

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    acme_client test1 https://localhost/dir; # defined but not used

    server {
        listen %%PORT_8080%%;
        server_name example.com;

    }
}

EOF

my ($code, $log) = $t->test_config();

ok($code == 0, 'no config syntax errors');

like($log, qr/ACME client "test1" is defined but not used/,
	'got "client defined but not used" as expected');

# config 2

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    acme_client test1 https://localhost/dir;

    server {
        listen %%PORT_8080%%;
        server_name example.com;

        acme test1;
    }

    server {
        listen %%PORT_8081%%;
        server_name _; # invalid domain name for ACME

        acme test1;
    }
}

EOF

($code, $log) = $t->test_config();

like($log, qr/unsupported domain format "_" used by ACME client "test1", ignored/,
	'got "unsupported domain format" as expected');
like($log, qr/no valid domain name defined in server block at .+ for ACME client "test1"/,
	'got "no valid domain name defined" as expected');
ok($code != 0, 'config syntax error as expected');


###############################################################################
