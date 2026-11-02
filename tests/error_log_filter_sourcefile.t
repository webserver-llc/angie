#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log filters with sourcefile

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

my $t = Test::Nginx->new()->has(qw/http rewrite proxy debug/)
	->plan(10)->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u1 {
        server unix:%%TESTDIR%%/no-such.sock; # nobody should listen on it
        server 127.0.0.1:8082;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {

            error_log http_nofilter_slash.log;

            # the failed connection error might come from
            # either ngx_connection.c or ngx_event_connect.c

            # simple match (good)
            error_log filtered_file.log filter=sourcefile:ngx_connection;
            error_log filtered_file.log filter=sourcefile:ngx_event_connect;

            # simple match (missing)
            error_log filtered_file_miss.log filter=sourcefile:ngx_http;

            # file match combined with msg match (good)
            error_log filtered_file_multi.log
                                           filter=sourcefile:ngx_connection
                                           filter=logline:localhost;

            error_log filtered_file_multi.log
                                           filter=sourcefile:ngx_event_connect
                                           filter=logline:localhost;

            # file match combined with msg match (bad)
            error_log filtered_file_multi_bad.log
                                           filter=sourcefile:ngx_connection
                                           filter=logline:non_existing;

            error_log filtered_file_multi_bad.log
                                           filter=sourcefile:ngx_event_connect
                                           filter=logline:non_existing;

            proxy_pass http://u1;
        }

        location /bad {

            error_log http_nofilter_bad.log;

            error_log filtered_file_bad.log filter=sourcefile:ngx_http_proxy;

            # set empty variable to trigger runtime error on proxying
            set \$missing "";
            proxy_pass http://\$missing;
            # generates error without system-specific errno and paths
        }
    }

    server {
        listen       127.0.0.1:8082;

        location / {
            return 200 "PROXIED";
        }
    }
}

EOF


$t->run();

like(http_get('/'), qr/PROXIED/, 'visited upstream');
like(http_get('/bad'), qr/500/, 'triggered bad upstream');

$t->stop();


is($t->find_in_file('filtered_file.log', qr/.+/), 1,
	'one line on file match');
is($t->find_in_file('filtered_file.log', qr/127\.0\.0\.1/), 1,
	'substring match on file is correct');

is($t->find_in_file('filtered_file_miss.log', qr/.+/), 0,
	'empty file_miss.log');

is($t->find_in_file('filtered_file_multi.log', qr/.+/), 1,
	'one line on file_multi match');
is($t->find_in_file('filtered_file_multi.log', qr/127\.0\.0\.1/), 1,
	'substring match on file_multi is correct');

is($t->find_in_file('filtered_file_bad.log', qr/.+/), 1,
	'one line on file match in /bad');
is($t->find_in_file('filtered_file_bad.log', qr/invalid URL/), 1,
	'substring match on file in /bad is correct');

is($t->find_in_file('filtered_file_multi_bad.log', qr/.+/), 0,
	'empty multi_bad.log');

