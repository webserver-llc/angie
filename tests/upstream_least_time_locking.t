#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Regression test for a locking bug in least_time balancer:
# when all peers are down, the peers rwlock was not released
# in the "failed" path, causing 100% CPU on subsequent requests.

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

my $t = Test::Nginx->new()
	->has(qw/upstream_least_time upstream_zone http/)
	->plan(2);

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        zone u 128k;
        server 127.0.0.1:8081 down;
        server 127.0.0.1:8082 down;
        least_time header;
    }

    server {
        listen 127.0.0.1:8080;

        location / {
            proxy_pass http://u;
        }
    }
}

EOF

$t->run();

# First request: all peers are down, balancer returns 502.
# Without the fix, the write lock on the upstream zone is leaked.
like(http_get('/'), qr/502 Bad/, 'all peers down returns 502');

# Second request: without the fix, this would spin on the leaked
# rwlock, causing 100% CPU and a test timeout.
like(http_get('/'), qr/502 Bad/, 'second request still returns 502');
