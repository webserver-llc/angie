#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log with user-defined tags

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


my $t = Test::Nginx->new()->has(qw/http/)
	->plan(8)->write_file_expand('nginx.conf', <<'EOF');

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

            log_not_found on;

            error_log_user_tag "$arg_tag1";
            error_log_user_tag "$arg_tag2";

            error_log %%TESTDIR%%/filtered_usertag1.log
                      filter=tag:foo
                      filter=tag:bar;

            error_log %%TESTDIR%%/filtered_usertag2.log
                      filter=tag:hello
                      filter=tag:world;

            error_log %%TESTDIR%%/filtered_usertag-all.log;
        }
    }
}

EOF


$t->run();

like(http_get('/notags'), qr/404/, 'query without user tags');
like(http_get('/fb?tag1=bar&tag2=foo'), qr/404/, 'query with foo/bar');
like(http_get('/hw?tag1=hello&tag2=world'), qr/404/, 'query with hello/world');

$t->stop();

is($t->find_in_file('filtered_usertag-all.log', 'request_line:'), 3,
	'logged into filtered_usertag-all.log');

is($t->find_in_file('filtered_usertag1.log', 'request_line:'), 1,
	'single message in filtered_usertag1.log');
is($t->find_in_file('filtered_usertag1.log', qr/GET \/fb/), 1,
	'filtered tag1 correct message');

is($t->find_in_file('filtered_usertag2.log', 'request_line:'), 1,
	'single message in filtered_usertag2.log');
is($t->find_in_file('filtered_usertag2.log', qr/GET \/hw/), 1,
	'filtered tag2 correct message');

