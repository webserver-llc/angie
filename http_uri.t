#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for URI normalization.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(8)
	->write_file_expand('nginx.conf', <<'EOF')->run();

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            add_header  X-URI  "x $uri x";
            return      204;
        }
    }
}

EOF

###############################################################################

local $TODO = 'not yet' unless $t->has_version('1.17.5');

like(http_get('/foo/bar%'), qr/400 Bad/, 'percent');
like(http_get('/foo/bar%1'), qr/400 Bad/, 'percent digit');

like(http_get('/foo/bar/.?args'), qr!x /foo/bar/ x!, 'dot args');
like(http_get('/foo/bar/.#frag'), qr!x /foo/bar/ x!, 'dot frag');
like(http_get('/foo/bar/..?args'), qr!x /foo/ x!, 'dot dot args');
like(http_get('/foo/bar/..#frag'), qr!x /foo/ x!, 'dot dot frag');
like(http_get('/foo/bar/.'), qr!x /foo/bar/ x!, 'trailing dot');
like(http_get('/foo/bar/..'), qr!x /foo/ x!, 'trailing dot dot');

###############################################################################
