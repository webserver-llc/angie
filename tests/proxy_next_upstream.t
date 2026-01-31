#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Maxim Dounin

# Tests for http proxy module, proxy_next_upstream directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream u2 {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream u3 {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082 down;
    }

    upstream u4 {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://u;
            proxy_next_upstream http_500 http_404;
        }

        location /all/ {
            proxy_pass http://u2;
            proxy_next_upstream http_500 http_404;
            error_page 404 /all/404;
            proxy_intercept_errors on;
        }

        location /all/404 {
            return 200 "$upstream_addr\n";
        }

        location /down {
            proxy_pass http://u3;
            proxy_next_upstream http_404;
        }

        location /nonext {
            proxy_pass http://u4/500;
            proxy_next_upstream http_500;
            proxy_next_upstream_tries 1;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 404;
        }
        location /ok {
            return 200 "AND-THIS\n";
        }
        location /500 {
            return 500;
        }

        location /all/ {
            return 404;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 200 "TEST-OK-IF-YOU-SEE-THIS\n";
        }

        location /all/ {
            return 404;
        }
    }
}

EOF

$t->run();

###############################################################################

my ($p1, $p2) = (port(8081), port(8082));

# check if both request fallback to a backend
# which returns valid response

like(http_get('/'), qr/SEE-THIS/, 'proxy request');
like(http_get('/'), qr/SEE-THIS/, 'second request');

# make sure backend isn't switched off after
# proxy_next_upstream http_404

like(http_get('/ok') . http_get('/ok'), qr/AND-THIS/, 'not down');

# next upstream on http_500

like(http_get('/500'), qr/SEE-THIS/, 'request 500');
like(http_get('/500'), qr/SEE-THIS/, 'request 500 second');

# make sure backend switched off with http_500

unlike(http_get('/ok') . http_get('/ok'), qr/AND-THIS/, 'down after 500');

# make sure all backends are tried once

like(http_get('/all/rr'),
	qr/^127.0.0.1:($p1, 127.0.0.1:$p2|$p2, 127.0.0.1:$p1)$/mi,
	'all tried once');

# make sure backend marked as down doesn't count towards "no live upstreams"
# after all backends are tried with http_404

like(http_get('/down/'), qr/Not Found/, 'all tried with down');

# make sure backend is switched off with http_500
# if switching to next upstream is not possible

like(http_get('/nonext'), qr/500 Internal|SEE-THIS/, 'request nonext');
like(http_get('/nonext'), qr/500 Internal|SEE-THIS/, 'request nonext second');
like(http_get('/nonext'), qr/SEE-THIS/, 'down after nonext');

###############################################################################
