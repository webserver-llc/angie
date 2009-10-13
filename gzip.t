#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx gzip filter module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT :gzip /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has('gzip')->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

master_process off;
daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location / {
            gzip on;
        }
        location /proxy/ {
            gzip on;
            proxy_pass http://127.0.0.1:8080/local/;
        }
        location /local/ {
            gzip off;
            alias %%TESTDIR%%/;
        }
    }
}

EOF

$t->write_file('index.html', 'X' x 64);

$t->run();

###############################################################################

my $r;

$r = http_gzip_request('/');
like($r, qr/^Content-Encoding: gzip/m, 'gzip');
http_gzip_like($r, qr/^X{64}\Z/, 'gzip content correct');

$r = http_gzip_request('/proxy/');
like($r, qr/^Content-Encoding: gzip/m, 'gzip proxied');
http_gzip_like($r, qr/^X{64}\Z/, 'gzip proxied content');

# Accept-Ranges headers should be cleared

unlike(http_gzip_request('/'), qr/Accept-Ranges/im, 'cleared accept-ranges');
unlike(http_gzip_request('/proxy/'), qr/Accept-Ranges/im,
	'cleared headers from proxy');

###############################################################################
