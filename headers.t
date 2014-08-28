#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for headers module.

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

my $t = Test::Nginx->new()->has(qw/http/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header   X-URI $uri;
        add_header   X-Always $uri always;
        expires epoch;

        location /t1 {
        }

        location /nx {
        }
    }
}

EOF

$t->write_file('t1', '');
$t->try_run('no add_header always')->plan(6);

###############################################################################

my $r;

# test for header field presence

$r = http_get('/t1');
like($r, qr/Cache-Control/, 'good expires');
like($r, qr/X-URI/, 'good add_header');
like($r, qr/X-Always/, 'good add_header always');

$r = http_get('/nx');
unlike($r, qr/Cache-Control/, 'bad expires');
unlike($r, qr/X-URI/, 'bad add_header');
like($r, qr/X-Always/, 'bad add_header always');

###############################################################################
