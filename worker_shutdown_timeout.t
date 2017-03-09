#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for worker_shutdown_timeout directive.

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

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
worker_shutdown_timeout 10ms;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / { }
    }
}

EOF

$t->try_run('no worker_shutdown_timeout')->plan(1);

###############################################################################

my $s = http('', start => 1);

kill 'HUP', $t->read_file('nginx.pid');
sleep 1;

is(http_get('/', socket => $s) || '', '', 'worker_shutdown_timeout');

###############################################################################
