#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx gzip filter module, preallocation sizes with various
# settings.

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

my $t = Test::Nginx->new()->has(qw/http gzip/)->plan(50);

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

        location / {
            gzip on;
        }

        location /max/ {
            alias %%TESTDIR%%/;
            gzip on;
            gzip_window 32k;
            gzip_hash 128k;
        }

        location /min/ {
            alias %%TESTDIR%%/;
            gzip on;
            gzip_window 512;
            gzip_hash 512;
        }

        location /minw/ {
            alias %%TESTDIR%%/;
            gzip on;
            gzip_window 512;
            gzip_hash 128k;
        }

        location /minh/ {
            alias %%TESTDIR%%/;
            gzip on;
            gzip_window 32k;
            gzip_hash 512;
        }
    }
}

EOF

$t->write_file('64.html', 'X' x 64);
$t->write_file('512.html', 'X' x 512);
$t->write_file('1k.html', 'X' x 1024);
$t->write_file('2k.html', 'X' x 2048);
$t->write_file('4k.html', 'X' x 4096);
$t->write_file('8k.html', 'X' x 8196);
$t->write_file('16k.html', 'X' x 16384);
$t->write_file('32k.html', 'X' x 32768);
$t->write_file('64k.html', 'X' x 65536);
$t->write_file('128k.html', 'X' x 131072);

$t->run();

###############################################################################

http_gzip_like(http_gzip_request('/64.html'), qr/^X{64}\Z/, 'gzip 64');
http_gzip_like(http_gzip_request('/512.html'), qr/^X{512}\Z/, 'gzip 512');
http_gzip_like(http_gzip_request('/1k.html'), qr/^X{1024}\Z/, 'gzip 1k');
http_gzip_like(http_gzip_request('/2k.html'), qr/^X{2048}\Z/, 'gzip 2k');
http_gzip_like(http_gzip_request('/4k.html'), qr/^X{2048}X+\Z/, 'gzip 4k');
http_gzip_like(http_gzip_request('/8k.html'), qr/^X{2048}X+\Z/, 'gzip 8k');
http_gzip_like(http_gzip_request('/16k.html'), qr/^X{2048}X+\Z/, 'gzip 16k');
http_gzip_like(http_gzip_request('/32k.html'), qr/^X{2048}X+\Z/, 'gzip 32k');
http_gzip_like(http_gzip_request('/64k.html'), qr/^X{2048}X+\Z/, 'gzip 64k');
http_gzip_like(http_gzip_request('/128k.html'), qr/^X{2048}X+\Z/, 'gzip 128k');

http_gzip_like(http_gzip_request('/max/64.html'), qr/^X+\Z/, 'gzip max 64');
http_gzip_like(http_gzip_request('/max/512.html'), qr/^X+\Z/, 'gzip max 512');
http_gzip_like(http_gzip_request('/max/1k.html'), qr/^X+\Z/, 'gzip max 1k');
http_gzip_like(http_gzip_request('/max/2k.html'), qr/^X+\Z/, 'gzip max 2k');
http_gzip_like(http_gzip_request('/max/4k.html'), qr/^X+\Z/, 'gzip max 4k');
http_gzip_like(http_gzip_request('/max/8k.html'), qr/^X+\Z/, 'gzip max 8k');
http_gzip_like(http_gzip_request('/max/16k.html'), qr/^X+\Z/, 'gzip max 16k');
http_gzip_like(http_gzip_request('/max/32k.html'), qr/^X+\Z/, 'gzip max 32k');
http_gzip_like(http_gzip_request('/max/64k.html'), qr/^X+\Z/, 'gzip max 64k');
http_gzip_like(http_gzip_request('/max/128k.html'), qr/^X+\Z/, 'gzip max 128k');

http_gzip_like(http_gzip_request('/min/64.html'), qr/^X+\Z/, 'gzip min 64');
http_gzip_like(http_gzip_request('/max/512.html'), qr/^X+\Z/, 'gzip min 512');
http_gzip_like(http_gzip_request('/min/1k.html'), qr/^X+\Z/, 'gzip min 1k');
http_gzip_like(http_gzip_request('/min/2k.html'), qr/^X+\Z/, 'gzip min 2k');
http_gzip_like(http_gzip_request('/min/4k.html'), qr/^X+\Z/, 'gzip min 4k');
http_gzip_like(http_gzip_request('/min/8k.html'), qr/^X+\Z/, 'gzip min 8k');
http_gzip_like(http_gzip_request('/min/16k.html'), qr/^X+\Z/, 'gzip min 16k');
http_gzip_like(http_gzip_request('/min/32k.html'), qr/^X+\Z/, 'gzip min 32k');
http_gzip_like(http_gzip_request('/min/64k.html'), qr/^X+\Z/, 'gzip min 64k');
http_gzip_like(http_gzip_request('/min/128k.html'), qr/^X+\Z/, 'gzip min 128k');

http_gzip_like(http_gzip_request('/minw/64.html'), qr/^X+\Z/,
	'gzip min window 64');
http_gzip_like(http_gzip_request('/minw/512.html'), qr/^X+\Z/,
	'gzip min window 512');
http_gzip_like(http_gzip_request('/minw/1k.html'), qr/^X+\Z/,
	'gzip min window 1k');
http_gzip_like(http_gzip_request('/minw/2k.html'), qr/^X+\Z/,
	'gzip min window 2k');
http_gzip_like(http_gzip_request('/minw/4k.html'), qr/^X+\Z/,
	'gzip min window 4k');
http_gzip_like(http_gzip_request('/minw/8k.html'), qr/^X+\Z/,
	'gzip min window 8k');
http_gzip_like(http_gzip_request('/minw/16k.html'), qr/^X+\Z/,
	'gzip min window 16k');
http_gzip_like(http_gzip_request('/minw/32k.html'), qr/^X+\Z/,
	'gzip min window 32k');
http_gzip_like(http_gzip_request('/minw/64k.html'), qr/^X+\Z/,
	'gzip min window 64k');
http_gzip_like(http_gzip_request('/minw/128k.html'), qr/^X+\Z/,
	'gzip min window 128k');

http_gzip_like(http_gzip_request('/minh/64.html'), qr/^X+\Z/,
	'gzip min hash 64');
http_gzip_like(http_gzip_request('/minh/512.html'), qr/^X+\Z/,
	'gzip min hash 512');
http_gzip_like(http_gzip_request('/minh/1k.html'), qr/^X+\Z/,
	'gzip min hash 1k');
http_gzip_like(http_gzip_request('/minh/2k.html'), qr/^X+\Z/,
	'gzip min hash 2k');
http_gzip_like(http_gzip_request('/minh/4k.html'), qr/^X+\Z/,
	'gzip min hash 4k');
http_gzip_like(http_gzip_request('/minh/8k.html'), qr/^X+\Z/,
	'gzip min hash 8k');
http_gzip_like(http_gzip_request('/minh/16k.html'), qr/^X+\Z/,
	'gzip min hash 16k');
http_gzip_like(http_gzip_request('/minh/32k.html'), qr/^X+\Z/,
	'gzip min hash 32k');
http_gzip_like(http_gzip_request('/minh/64k.html'), qr/^X+\Z/,
	'gzip min hash 64k');
http_gzip_like(http_gzip_request('/minh/128k.html'), qr/^X+\Z/,
	'gzip min hash 128k');

###############################################################################
