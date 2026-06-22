#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for rewrite "goto" directive.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(11)
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

        if ($arg_s) {
            goto @named;
        }

        location /srv-if {
            return 200 "not-named";
        }

        # basic unconditional goto
        location /basic {
            goto @named;
        }

        # conditional goto inside if block
        location /conditional {
            if ($arg_c) {
                goto @named;
            }
            return 200 "direct";
        }

        # check that $uri is NOT changed by goto
        location /uri {
            goto @uri_named;
        }

        # cycle: two named locations pointing at each other -> 500
        location /cycle {
            goto @cycle_a;
        }

        location @named {
            return 200 "named";
        }

        location @uri_named {
            return 200 "uri=$uri";
        }

        location @cycle_a {
            goto @cycle_b;
        }

        location @cycle_b {
            goto @cycle_a;
        }

        location /chain {
            goto @chain_first;
        }

        location @chain_first {
            goto @chain_second;
        }

        location @chain_second {
            return 200 "chained";
        }

        location /notfound {
            goto @no_such_location;
        }

        location /dead-code {
            goto @named;
            return 200 "dead";
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/basic'), qr/200 OK.*\bnamed\b/ms, 'basic goto');

like(http_get('/srv-if?s=1'), qr/200 OK.*\bnamed\b/ms,
	'server-level if goto taken');

like(http_get('/srv-if'), qr/200 OK.*\bnot-named\b/ms,
	'server-level if goto not taken');

like(http_get('/conditional?c=1'), qr/200 OK.*\bnamed\b/ms,
	'conditional goto taken');

like(http_get('/conditional'), qr/200 OK.*\bdirect\b/ms,
	'conditional goto not taken');

# $uri must remain /uri, not change to @uri_named
like(http_get('/uri'), qr!uri=/uri!ms, 'uri unchanged after goto');

# redirect cycle must be detected and result in 500
like(http_get('/cycle'), qr/500/, 'cycle detection');

like(http_get('/chain'), qr/200 OK.*\bchained\b/ms, 'named location chaining');

like(http_get('/notfound'), qr/500/, 'goto nonexistent named location');

my $r = http_get('/dead-code');
like($r, qr/200 OK.*\bnamed\b/ms, 'return after goto is dead code');
unlike($r, qr/dead/, 'dead code not reached');

###############################################################################
