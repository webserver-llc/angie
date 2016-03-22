#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for server_tokens directive.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ $CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen          127.0.0.1:8080;

        location /200 {
            return 200;
        }

        location /404 {
            return 404;
        }

        location /off {
            server_tokens off;

            location /off/200 {
                return 200;
            }

            location /off/404 {
                return 404;
            }
        }

        location /on {
            server_tokens on;

            location /on/200 {
                return 200;
            }

            location /on/404 {
                return 404;
            }
        }

        location /empty {
            server_tokens "";

            location /empty/200 {
                return 200;
            }

            location /empty/404 {
                return 404;
            }
        }

        location /var {
            server_tokens $arg_st;

            location /var/200 {
                return 200;
            }

            location /var/404 {
                return 404;
            }
        }
    }
}

EOF

$t->try_run('no server_tokens variable support')->plan(21);

###############################################################################

like(http_get('/200'), qr/Server: nginx\/\d+\.\d+\.\d+/, 'tokens default 200');
like(http_get('/404'), qr/Server: nginx\/\d+\.\d+\.\d+/, 'tokens default 404');
like(http_body('/404'), qr/nginx\/\d+\.\d+\.\d+/, 'tokens default 404 body');

like(http_get('/off/200'), qr/Server: nginx${CRLF}/, 'tokens off 200');
like(http_get('/off/404'), qr/Server: nginx${CRLF}/, 'tokens off 404');
like(http_body('/off/404'), qr/nginx(?!\/)/, 'tokens off 404 body');

like(http_get('/on/200'), qr/Server: nginx\/\d+\.\d+\.\d+/, 'tokens on 200');
like(http_get('/on/404'), qr/Server: nginx\/\d+\.\d+\.\d+/, 'tokens on 404');
like(http_body('/on/404'), qr/nginx\/\d+\.\d+\.\d+/, 'tokens on 404 body');

like(http_get('/empty/200'), qr/Server: nginx${CRLF}/, 'tokens empty 200');
like(http_get('/empty/404'), qr/Server: nginx${CRLF}/, 'tokens empty 404');
like(http_body('/empty/404'), qr/nginx(?!\/)/, 'tokens empty 404 body');

like(http_get('/var/200?st=off'), qr/Server: nginx${CRLF}/,
	'tokens var off 200');
like(http_get('/var/404?st=off'), qr/Server: nginx${CRLF}/,
	'tokens var off 404');
like(http_body('/var/404?st=off'), qr/nginx(?!\/)/, 'tokens var off 404 body');

like(http_get('/var/200?st=on'), qr/Server: nginx\/\d+\.\d+\.\d+/,
	'tokens var on 200');
like(http_get('/var/404?st=on'), qr/Server: nginx\/\d+\.\d+\.\d+/,
	'tokens var on 404');
like(http_body('/var/404?st=on'), qr/nginx\/\d+\.\d+\.\d+/,
	'tokens var on 404 body');

like(http_get('/var/200'), qr/Server: nginx${CRLF}/, 'tokens var empty 200');
like(http_get('/var/404'), qr/Server: nginx${CRLF}/, 'tokens var empty 404');
like(http_body('/var/404'), qr/nginx(?!\/)/, 'tokens var empty 404 body');

###############################################################################

sub http_body {
	my ($uri) = shift;
	return http_get($uri) =~ /.*?\x0d\x0a?\x0d\x0a?(.*)/ms && $1;
}

###############################################################################
