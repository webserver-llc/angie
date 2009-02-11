#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for rewrite module.

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

my $t = Test::Nginx->new()->has('rewrite')->plan(5)
	->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    access_log    off;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            rewrite ^ http://example.com/ redirect;
        }

        location /add {
            rewrite ^ http://example.com/?c=d redirect;
        }

        location /no {
            rewrite ^ http://example.com/?c=d? redirect;
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/'), qr!^Location: http://example.com/\x0d?$!ms, 'simple');
like(http_get('/?a=b'), qr!^Location: http://example.com/\?a=b\x0d?$!ms,
	'simple with args');
like(http_get('/add'), qr!^Location: http://example.com/\?c=d\x0d?$!ms,
	'add args');

like(http_get('/add?a=b'), qr!^Location: http://example.com/\?c=d&a=b\x0d?$!ms,
	'add args with args');

like(http_get('/no?a=b'), qr!^Location: http://example.com/\?c=d\x0d?$!ms,
	'no args with args');

###############################################################################
