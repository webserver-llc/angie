#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for nginx limit_req module, limit_req_dry_run directive.

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

my $t = Test::Nginx->new()->has(qw/http limit_req/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_req_zone  $binary_remote_addr  zone=one:1m   rate=1r/m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        limit_req_dry_run  on;

        location /delay {
            limit_req    zone=one  burst=2;
        }

        location /reject {
            limit_req    zone=one;
        }

        location /reject/off {
            limit_req    zone=one;

            limit_req_dry_run off;
        }
    }
}

EOF

$t->write_file('delay', 'SEE-THIS');
$t->write_file('reject', 'SEE-THIS');
$t->try_run('no limit_req_dry_run')->plan(6);

###############################################################################

like(http_get('/delay'), qr/^HTTP\/1.. 200 /m, 'dry run');
like(http_get('/delay'), qr/^HTTP\/1.. 200 /m, 'dry run - not delayed');
like(http_get('/reject'), qr/^HTTP\/1.. 200 /m, 'dry run - not rejected');

like(http_get('/reject/off'), qr/^HTTP\/1.. 503 /m, 'dry run off - rejected');

$t->stop();

like($t->read_file('error.log'), qr/delaying request, dry/, 'log - delay');
like($t->read_file('error.log'), qr/limiting requests, dry/, 'log - reject');

###############################################################################
