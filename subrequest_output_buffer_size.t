#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for subrequest_output_buffer_size directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy ssi/)
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

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /longok {
            proxy_pass http://127.0.0.1:8081/long;
            subrequest_output_buffer_size 42k;
        }

        location /ssi {
            ssi on;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
    }
}

EOF

$t->write_file('ssi.html',
	'<!--#include virtual="/$arg_c" set="x" -->' .
	'set: <!--#echo var="x" -->');

$t->write_file('length', 'TEST-OK-IF-YOU-SEE-THIS');
$t->write_file('long', 'x' x 40000);
$t->write_file('empty', '');

$t->try_run('no subrequest_output_buffer_size')->plan(4);

###############################################################################

my ($r, $n);

like(http_get('/ssi.html?c=length'), qr/SEE-THIS/, 'request');
like(http_get('/ssi.html?c=empty'), qr/200 OK/, 'empty');
unlike(http_get('/ssi.html?c=long'), qr/200 OK/, 'long default');
like(http_get('/ssi.html?c=longok'), qr/200 OK/, 'long ok');

###############################################################################
