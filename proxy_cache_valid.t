#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http proxy cache, the proxy_cache_valid directive
# used with the caching parameters set in the response header.

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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(8)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass    http://127.0.0.1:8081;
            proxy_cache   NAME;

            proxy_cache_valid  1m;

            add_header X-Cache-Status $upstream_cache_status;
        }
    }
    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            add_header Cache-Control $http_x_cc;
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

like(get('/t.html?1', 'X-CC: max-age=1'), qr/MISS/, 'max-age');
like(get('/t.html?2', 'X-CC: max-age=1, s-maxage=10'), qr/MISS/, 's-maxage');
like(http_get('/t.html?3'), qr/MISS/, 'proxy_cache_valid');

$t->write_file('t.html', 'NOOP');

like(http_get('/t.html?1'), qr/HIT/, 'max-age cached');
like(http_get('/t.html?2'), qr/HIT/, 's-maxage cached');
like(http_get('/t.html?3'), qr/HIT/, 'proxy_cache_valid cached');

select undef, undef, undef, 2.1;

# Cache-Control in the response header overrides proxy_cache_valid

like(http_get('/t.html?1'), qr/EXPIRED/, 'max-age ceased');
like(http_get('/t.html?2'), qr/HIT/, 's-maxage overrides max-age');

###############################################################################

sub get {
	my ($url, $extra) = @_;
	return http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
}

###############################################################################
