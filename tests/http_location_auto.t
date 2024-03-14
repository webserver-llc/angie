#!/usr/bin/perl

# (C) 2023-2024 Web Server LLC
# (C) Maxim Dounin

# Tests for location selection, an auto_redirect edge case.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(11)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_hide_header X-Location;
        add_header X-Location unset;

        # As of nginx 1.5.4, this results in the following
        # location tree:
        #
        #         "/a-b"
        # "/a-a"          "/a/"
        #
        # A request to "/a" is expected to match "/a/" with auto_redirect,
        # but with such a tree it tests locations "/a-b", "/a-a" and then
        # falls back to null location.
        #
        # Key factor is that "-" is less than "/".

        location /a/  { proxy_pass http://127.0.0.1:8080/a-a; }
        location /a-a { add_header X-Location a-a; return 204; }
        location /a-b { add_header X-Location a-b; return 204; }
        location /cc /d/ =/e/ =/f/ /a-a/ =/f {
            rewrite ^ /a-b break;
            proxy_pass http://127.0.0.1:8080;
            auto_redirect default;
        }
        location /g/ { auto_redirect on; }
        location /h/ {
            auto_redirect off;
            proxy_pass http://127.0.0.1:8080;
        }
        location /i/ { auto_redirect default; }
    }
}

EOF

$t->run();

###############################################################################

my $p = port(8080);

like(http_get('/a'), qr!301 Moved.*Location: http://localhost:$p/a/\x0d?$!ms,
     'auto redirect');
like(http_get('/a/'), qr/X-Location: unset/, 'match a');
like(http_get('/a-a'), qr/X-Location: a-a/, 'match a-a');
like(http_get('/a-b'), qr/X-Location: a-b/, 'match a-b');
like(http_get('/c'), qr/404 Not Found/, 'no redirect for /c');
like(http_get('/d'), qr!301 Moved.*Location: http://localhost:$p/d/\x0d?$!ms,
     'auto redirect for /d/');
like(http_get('/e'), qr!301 Moved.*Location: http://localhost:$p/e/\x0d?$!ms,
     'auto redirect for /e/');
like(http_get('/f'), qr/X-Location: unset/, 'no redirect for /f');
like(http_get('/g'), qr!301 Moved.*Location: http://localhost:$p/g/\x0d?$!ms,
     'auto_redirect on');
like(http_get('/h'), qr/404 Not Found/, 'auto_redirect off');
like(http_get('/i'), qr/404 Not Found/, 'auto_redirect default');

###############################################################################
