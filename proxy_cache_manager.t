#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http proxy cache, manager parameters.

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

plan(skip_all => 'long test') unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http proxy cache/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  max_size=0  keys_zone=NAME:1m
                       manager_sleep=5  manager_files=2  manager_threshold=10;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass    http://127.0.0.1:8081;
            proxy_cache   NAME;

            proxy_cache_valid   any   1m;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->try_run('no manager params')->plan(2);

###############################################################################

# wait for cache manager start

sleep 1;

http_get("/t.html?$_") for (1 .. 5);

# wait for cache manager process

sleep 10;

opendir(my $dh, $t->testdir() . '/cache');
my $files = grep { ! /^\./ } readdir($dh);
is($files, 3, 'manager files');

sleep 5;

opendir($dh, $t->testdir() . '/cache');
$files = grep { ! /^\./ } readdir($dh);
is($files, 1, 'manager sleep');

###############################################################################
