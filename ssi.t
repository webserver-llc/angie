#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx ssi module.

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

my $t = Test::Nginx->new()->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location / {
            ssi on;
        }
        location /proxy/ {
            ssi on;
            proxy_pass http://127.0.0.1:8080/local/;
        }
        location /local/ {
            ssi off;
            alias %%TESTDIR%%/;
        }
    }
}

EOF

$t->write_file('test1.html', 'X<!--#echo var="arg_test" -->X');
$t->write_file('test2.html',
	'X<!--#include virtual="/test1.html?test=test" -->X');
$t->write_file('test3.html',
	'X<!--#set var="blah" value="test" --><!--#echo var="blah" -->X');
$t->write_file('test-empty1.html', 'X<!--#include virtual="/empty.html" -->X');
$t->write_file('test-empty2.html',
	'X<!--#include virtual="/local/empty.html" -->X');
$t->write_file('empty.html', '');

$t->run();

###############################################################################

like(http_get('/test1.html'), qr/^X\(none\)X$/m, 'echo no argument');
like(http_get('/test1.html?test='), qr/^XX$/m, 'empty argument');
like(http_get('/test1.html?test=test'), qr/^XtestX$/m, 'argument');
like(http_get('/test1.html?test=test&a=b'), qr/^XtestX$/m, 'argument 2');
like(http_get('/test1.html?a=b&test=test'), qr/^XtestX$/m, 'argument 3');
like(http_get('/test1.html?a=b&test=test&d=c'), qr/^XtestX$/m, 'argument 4');
like(http_get('/test1.html?atest=a&testb=b&ctestc=c&test=test'), qr/^XtestX$/m,
	'argument 5');

like(http_get('/test2.html'), qr/^XXtestXX$/m, 'argument via include');

like(http_get('/test3.html'), qr/^XtestX$/m, 'set');

# Last-Modified and Accept-Ranges headers should be cleared

unlike(http_get('/test1.html'), qr/Last-Modified|Accept-Ranges/im,
	'cleared headers');
unlike(http_get('/proxy/test1.html'), qr/Last-Modified|Accept-Ranges/im,
	'cleared headers from proxy');

like(http_get('/test-empty1.html'), qr/HTTP/, 'empty with ssi');
like(http_get('/test-empty2.html'), qr/HTTP/, 'empty without ssi');

###############################################################################
