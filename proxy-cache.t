#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http proxy cache.

###############################################################################

use warnings;
use strict;

use Test::More tests => 2;

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
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=NAME:10m
                       inactive=5m     clean_time=2h00m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass    http://127.0.0.1:8081;

            proxy_cache   NAME;

            proxy_cache_valid   200 302  1h;
            proxy_cache_valid   301      1d;
            proxy_cache_valid   any      1m;

            proxy_cache_min_uses  1;

            proxy_cache_use_stale   error  timeout invalid_header http_500;
        }
    }
    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/t.html'), qr/SEE-THIS/, 'proxy request');

$t->write_file('t.html', 'NOOP');
like(http_get('/t.html'), qr/SEE-THIS/, 'proxy request cached');

###############################################################################
