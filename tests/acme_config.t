#!/usr/bin/perl

# (C) 2025 Web Server LLC

# ACME tests for handling some uncommon or invalid configurations

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

my $t = Test::Nginx->new()->has(qw/acme http_ssl/)->plan(10);

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

is($code, 0, 'no config syntax errors');

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

isnt($code, 0, 'config syntax error as expected');

like($log, qr/unsupported domain format "_" used by ACME client "test1", ignored/,
	'got "unsupported domain format" as expected');
like($log, qr/no valid domain name defined in server block at .+ for ACME client "test1"/,
	'got "no valid domain name defined" as expected');

# config 3

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # client not defined
    # acme_client test1 https://localhost/dir;

    server {
        listen %%PORT_8080%%;
        server_name example.com;

        # but used
        acme test1;
    }
}

EOF

($code, $log) = $t->test_config();

isnt($code, 0, 'config syntax error as expected');

like($log, qr/ACME client "test1" is not defined but referenced/,
	'got "client not defined but referenced" as expected');

# config 4

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # client not defined
    # acme_client test1 https://localhost/dir;

    server {
        listen %%PORT_8080%%;
        server_name example.com;

        location / {
            internal;

            # but used
            acme_hook test1 ;

            fastcgi_pass localhost:%%PORT_9000%%;

            fastcgi_param ACME_CLIENT           $acme_hook_client;
            fastcgi_param ACME_HOOK             $acme_hook_name;
            fastcgi_param ACME_CHALLENGE        $acme_hook_challenge;
            fastcgi_param ACME_DOMAIN           $acme_hook_domain;
            fastcgi_param ACME_TOKEN            $acme_hook_token;
            fastcgi_param ACME_KEYAUTH          $acme_hook_keyauth;

            fastcgi_param REQUEST_URI           $request_uri;
        }
    }

}

EOF

($code, $log) = $t->test_config();

isnt($code, 0, 'config syntax error as expected');

like($log, qr/ACME client "test1" is not defined but referenced/,
	'got "client not defined but referenced" as expected');

# config 5

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # client disabled
    acme_client test1 https://localhost/dir enabled=off;

    server {
        listen %%PORT_8443%% ssl;
        server_name example.com;

        # but acme_cert* variables used
        ssl_certificate      $acme_cert_test1;
        ssl_certificate_key  $acme_cert_key_test1;
    }
}

EOF

($code, $log) = $t->test_config();

SKIP: {
skip 'variables in ssl_certificate* directives not supported', 1
	if $log =~ /variables in "ssl_certificate" and "ssl_certificate_key" directives are not supported on this platform/;

is($code, 0, 'no config syntax errors');
}

###############################################################################

# Nginx.pm expects error.log to exist at exit time.  If Angie has never started
# during the session, this file is not created, so we must supply it to make
# the module's destructor happy.
$t->write_file('error.log', '') unless -f $t->testdir() . '/error.log';

