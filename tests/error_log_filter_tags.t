#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log filters with tags

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

my $t = Test::Nginx->new()->has(qw/http rewrite proxy/)
	->plan(9)->write_file_expand('nginx.conf', <<'EOF');

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

            error_log filtered_tag.log filter=tag:peer;

            # multiple tags with exact, substring and regex matches
            error_log filtered_tag_multi.log filter=tag:=http
                                             filter=tag:upstr
                                             filter=tag:~p.*e.*er;

            # one tag does not match ('=stream' to avoid matching 'upstream')
            error_log filtered_tag_multi_miss.log filter=tag:http
                                                  filter=tag:upstream
                                                  filter=tag:peer
                                                  filter=tag:=stream;

            # try to filter on unknown tag
            error_log filtered_unknown_tag.log filter=tag:unknown;

            proxy_pass http://u1;
        }

        location /bad_file.txt {
            # produce entry in error.log for 404
            log_not_found on;

            error_log filtered_404.log filter=tag:http;
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
like(http_get('/bad_file.txt'), qr/404/, 'triggered missing file');

$t->stop();

is($t->find_in_file('filtered_tag.log', qr/.+/), 1,
	'filtered single line by tag');
is($t->find_in_file('filtered_tag.log', qr/while.+to upstream/), 1,
	'filtered tag correct message');

is($t->find_in_file('filtered_tag_multi.log', qr/.+/), 1,
	'filtered single line by multi tag');
is($t->find_in_file('filtered_tag_multi.log',
	qr/while.+to upstream/), 1, 'filtered multi tag correct message');

is($t->find_in_file('filtered_tag_multi_miss.log', qr/.+/), 0,
	'empty file with multi miss');

is($t->find_in_file('filtered_unknown_tag.log', qr/.+/), 0,
	'empty file with unknown tag');


is($t->find_in_file('filtered_404.log', qr/.+/), 1,
	'single line in filtered 404');

