#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for access_log with escape parameter.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format json     escape=json     $arg_a$arg_b$arg_c;
    log_format default  escape=default  $arg_a$arg_b$arg_c;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/json.log json;
        access_log %%TESTDIR%%/test.log default;
    }
}

EOF

$t->run();

###############################################################################

http_get('/?a="1 \\ ' . pack("n", 0x1b1c) . ' "&c=2');

$t->stop();

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.11.8');

is($t->read_file('json.log'), '\"1 \\\\ \u001B\u001C \"2' . "\n", 'json');
is($t->read_file('test.log'), '\x221 \x5C \x1B\x1C \x22-2' . "\n", 'default');

}

###############################################################################
