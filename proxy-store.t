#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for proxy_store functionality.

###############################################################################

use warnings;
use strict;

use Test::More tests => 5;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new();

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /store {
            proxy_pass http://127.0.0.1:8080/index.html;
            proxy_store on;
        }
        location /nostore {
            proxy_pass http://127.0.0.1:8080/index-nostore.html;
            proxy_store on;
        }
        location /index-nostore.html {
            add_header  X-Accel-Expires  0;
        }
    }
}

EOF

$t->write_file('index.html', 'SEE-THIS');
$t->write_file('index-nostore.html', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/store'), qr/SEE-THIS/, 'proxy request');
ok(-e $t->testdir() . '/store', 'result stored');

like(http_get('/nostore'), qr/SEE-THIS/, 'proxy request with x-accel-expires');

TODO: {
local $TODO = 'patch under review';

ok(!-e $t->testdir() . '/nostore', 'result not stored');
}

ok(scalar @{[ glob $t->testdir() . '/proxy_temp/*' ]} == 0, 'no temp files');

###############################################################################
