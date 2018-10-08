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

my $t = Test::Nginx->new()->has(qw/http/)->plan(1)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format none     escape=none     $arg_a$arg_b$arg_c;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/none.log none;
    }
}

EOF

$t->run();

###############################################################################

http_get('/?a="1 \\ ' . pack("n", 0x1b1c) . ' "&c=2');

$t->stop();

is($t->read_file('none.log'), '"1 \\ ' . pack("n", 0x1b1c) . " \"2\n", 'none');

###############################################################################
