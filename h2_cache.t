#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with cache.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2 qw/ :DEFAULT :frame /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 cache/)->plan(11)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache    keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080 http2;
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /cache {
            proxy_pass http://127.0.0.1:8081/;
            proxy_cache NAME;
            proxy_cache_valid 1m;
        }
        location /proxy_buffering_off {
            proxy_pass http://127.0.0.1:8081/;
            proxy_cache NAME;
            proxy_cache_valid 1m;
            proxy_buffering off;
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

# simple proxy cache test

my $sess = new_session();
my $sid = new_stream($sess, { path => '/cache/t.html' });
my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'proxy cache');

my $etag = $frame->{headers}->{'etag'};

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{length}, length 'SEE-THIS', 'proxy cache - DATA');
is($frame->{data}, 'SEE-THIS', 'proxy cache - DATA payload');

$t->write_file('t.html', 'NOOP');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/cache/t.html' },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'if-none-match', value => $etag }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 304, 'proxy cache conditional');

$t->write_file('t.html', 'SEE-THIS');

# request body with cached response

$sid = new_stream($sess, { path => '/cache/t.html', body_more => 1 });
h2_body($sess, 'TEST');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'proxy cache - request body');

h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" && $_->{flags} & 0x1 } @$frames;
ok($frame, 'proxy cache - request body - next');

# HEADERS could be received with fin, followed by DATA

$sess = new_session();
$sid = new_stream($sess, { path => '/cache/t.html?1', method => 'HEAD' });

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
push @$frames, $_ for @{h2_read($sess, all => [{ sid => $sid }])};
ok(!grep ({ $_->{type} eq "DATA" } @$frames), 'proxy cache HEAD - no body');

# proxy cache - expect no stray empty DATA frame

TODO: {
local $TODO = 'not yet';

$sess = new_session();
$sid = new_stream($sess, { path => '/cache/t.html?2' });

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
my @data = grep ({ $_->{type} eq "DATA" } @$frames);
is(@data, 1, 'proxy cache write - data frames');
is(join(' ', map { $_->{data} } @data), 'SEE-THIS', 'proxy cache write - data');
is(join(' ', map { $_->{flags} } @data), '1', 'proxy cache write - flags');

}

# HEAD on empty cache with proxy_buffering off

$sess = new_session();
$sid = new_stream($sess,
	{ path => '/proxy_buffering_off/t.html?1', method => 'HEAD' });

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
push @$frames, $_ for @{h2_read($sess, all => [{ sid => $sid }])};
ok(!grep ({ $_->{type} eq "DATA" } @$frames),
	'proxy cache HEAD buffering off - no body');

###############################################################################
