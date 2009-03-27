#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx limit_req module.

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

my $t = Test::Nginx->new()->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    limit_req_zone  $binary_remote_addr  zone=one:10m   rate=1r/m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location / {
            limit_req    zone=one  burst=1  nodelay;
        }
    }
}

EOF

$t->write_file('test1.html', 'XtestX');
$t->run();

###############################################################################

like(http_get('/test1.html'), qr/^HTTP\/1.. 200 /m, 'request');
http_get('/test1.html');
like(http_get('/test1.html'), qr/^HTTP\/1.. 503 /m, 'request rejected');

###############################################################################
