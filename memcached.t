#!/usr/bin/perl

# (C) Maxim Dounin

# Test for memcached backend.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require Cache::Memcached; };
plain(skip_all => 'Cache::Memcached not installed') if $@;

my $t = Test::Nginx->new()->has('rewrite')->has_daemon('memcached')->plan(3)
	->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

http {
    access_log    off;

    server {
        listen       localhost:8080;
        server_name  localhost;

        location / {
            set $memcached_key $uri;
            memcached_pass 127.0.0.1:8081;
        }

        location /next {
            set $memcached_key $uri;
            memcached_next_upstream  not_found;
            memcached_pass 127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon('memcached', '-l', '127.0.0.1', '-p', '8081');
$t->run();

###############################################################################

my $memd = Cache::Memcached->new(servers => [ '127.0.0.1:8081' ]);
$memd->set('/', 'SEE-THIS');

like(http_get('/'), qr/SEE-THIS/, 'memcached request');
like(http_get('/notfound'), qr/404/, 'memcached not found');
like(http_get('/next'), qr/404/, 'not found with memcached_next_upstream');

###############################################################################
