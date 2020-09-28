#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for the userid_flags directive.

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

my $t = Test::Nginx->new()->has(qw/http userid/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        userid         on;
        userid_name    test;
        userid_path    /0123456789;
        userid_domain  test.domain;

        location / {
            userid_flags samesite=strict;

            location /many {
                userid_flags httponly samesite=none secure;
            }
        }

        location /lax {
            userid_flags samesite=lax;
        }
    }
}

EOF

$t->write_file('index.html', '');
$t->write_file('lax', '');
$t->write_file('many', '');
$t->try_run('no userid_flags')->plan(3);

###############################################################################

like(http_get('/'), qr/samesite=strict/, 'strict');
like(http_get('/lax'), qr/samesite=lax/, 'lax');
like(http_get('/many'), qr/secure; httponly; samesite=none/, 'many');

###############################################################################
