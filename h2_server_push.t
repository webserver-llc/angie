#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 server push.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2;
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /prio {
            http2_push /t1;
            http2_push /t2;
            return 204;
        }

        location /expl {
            http2_push /push;
            http2_push /push2;

            location /expl/off {
                http2_push off;
            }
        }

        location /preload {
            http2_push_preload on;
            add_header Link "</push>; rel=preload";
            add_header X-Link $sent_http_link;
            return 200 SEE-THIS;
        }

        location /preload2 {
            http2_push_preload on;
            add_header Link "</push>; rel=preload";           # valid
            add_header Link "</push2 >; rel=preload";         # valid
            add_header Link "</push3>; rel=preloadX";         # not
            add_header Link '</push4>; rel="preload"';        # valid
            add_header Link '</push5>; rel="preloadX"';       # not
            add_header Link "</push6>; rel=preload; nopush";  # not
            add_header Link '</push7>; rel="foo"';            # not
            add_header Link '</push7>; rel="foo preload"';    # valid
            return 200 SEE-THIS;
        }

        location /preload/many {
            http2_push_preload on;
            add_header Link "</push>; rel=preload, </push2>; rel=preload";
            add_header Link "</push3>, </push4>; rel=preload";
            return 200 SEE-THIS;
        }

        location /preload/proxy {
            http2_push_preload on;
            proxy_pass http://127.0.0.1:8081/proxied;
        }

        location /proxied {
            add_header Link "</push>; rel=preload";
            add_header Link "</push2>; rel=preload";
            return 200 SEE-THIS;
        }

        location /both {
            http2_push /push;
            http2_push_preload on;
            add_header Link "</push>; rel=preload";
            return 200 SEE-THIS;
        }

        location /arg {
            http2_push $arg_push;
            return 204;
        }

        location /push {
            return 200 PROMISED;
        }
    }

    server {
        listen       127.0.0.1:8082 http2;
        server_name  max_pushes;

        http2_max_concurrent_pushes 2;
        http2_push /push;
        http2_push /push;
        http2_push /push;
    }
}

EOF

$t->write_file('t1', join('', map { sprintf "X%04dXXX", $_ } (1 .. 8202)));
$t->write_file('t2', 'SEE-THIS');
$t->write_file('explf', join('', map { sprintf "X%06dXXX", $_ } (1 .. 6553)));

$t->try_run('no http2_push')->plan(38);

###############################################################################

# preload & format

my $s = Test::Nginx::HTTP2->new();
my $sid = $s->new_stream({ path => '/preload' });
my $frames = $s->read(all => [{ sid => 1, fin => 1 }, { sid => 2, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok($frame, 'push promise');
is($frame->{headers}->{':authority'}, 'localhost', 'authority');
is($frame->{headers}->{':scheme'}, 'http', 'scheme');
is($frame->{headers}->{':method'}, 'GET', 'method');
is($frame->{headers}->{':path'}, '/push', 'path');
is($frame->{flags}, 4, 'flags');
is($frame->{promised}, 2, 'promised stream');

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} eq 2 } @$frames;
is($frame->{data}, 'PROMISED', 'promised stream payload');

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} eq $sid } @$frames;
is($frame->{headers}->{'x-link'}, '</push>; rel=preload', 'sent_http_link');

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/preload2' });
$frames = $s->read(all => [{ sid => 8, fin => 1 }], wait => 0.5);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 4, 'preload 2');

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/preload/many' });
$frames = $s->read(all => [{ sid => 8, fin => 1 }], wait => 0.5);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 3, 'preload many');

# preload proxy

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/preload/proxy' });
$frames = $s->read(all => [{ sid => 8, fin => 1 }], wait => 0.5);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 2, 'preload proxy');

# both h2_push & preload

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/both' });
$frames = $s->read(all => [{ sid => 8, fin => 1 }], wait => 0.5);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 2, 'h2_push and preload');

# h2_push

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [{ sid => 1, fin => 1 }, { sid => 2, fin => 1 }]);

($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok($frame, 'h2_push only');

# h2_push off

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/expl/off' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);

($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok(!$frame, 'h2_push off');

# h2_push $var

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/arg?push=/push' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);
($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok($frame, 'h2_push variable');

$sid = $s->new_stream({ path => '/arg?push=' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);
($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok(!$frame, 'h2_push variable empty');

$sid = $s->new_stream({ path => '/arg?push=off' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);
($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok(!$frame, 'h2_push variable off');

$sid = $s->new_stream({ path => '/arg?push=foo' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);
($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok(!$frame, 'h2_push variable relative path');

# SETTINGS_ENABLE_PUSH

$s = Test::Nginx::HTTP2->new();
$s->h2_settings(0, 0x2 => 0);
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);

($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok(!$frame, 'push setting disabled');

$s->h2_settings(0, 0x2 => 1);
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [{ sid => $sid, fin => 1 }, { sid => 2, fin => 1 }]);

($frame) = grep { $_->{type} eq "PUSH_PROMISE" } @$frames;
ok($frame, 'push setting enabled');

$s->h2_settings(0, 0x2 => 42);
$frames = $s->read(all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} =~ "GOAWAY" } @$frames;
is($frame->{'code'}, 1, 'push setting invalid - GOAWAY protocol error');
cmp_ok($frame->{'last_sid'}, '<', 5, 'push setting invalid - last sid');

# SETTINGS_MAX_CONCURRENT_STREAMS

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [
	{ sid => 1, fin => 1 },
	{ sid => 2, fin => 1 },
	{ sid => 4, fin => 1 }]);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 2, 'max pushes default');

$s = Test::Nginx::HTTP2->new();
$s->h2_settings(0, 0x3 => 1);
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [{ sid => 1, fin => 1 }, { sid => 2, fin => 1 }]);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 1, 'max pushes limited');

$s = Test::Nginx::HTTP2->new();
$s->h2_settings(0, 0x3 => 0);
$sid = $s->new_stream({ path => '/expl' });
$frames = $s->read(all => [{ type => 'PUSH_PROMISE' }], wait => 0.2);
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 0, 'max pushes disabled');

TODO: {
local $TODO = 'not yet' if $t->read_file('nginx.conf') =~ /aio on/;

# server push flow control & rst

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/explf' });
$frames = $s->read(all => [
	{ sid => 1, fin => 1 },
	{ sid => 2, length => 5 },
	{ sid => 4, fin => 4 }]);

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == 2 } @$frames;
is($frame->{length}, 5, 'flow control - pushed stream limited');
is($frame->{flags}, 0, 'flow control - pushed stream flags');

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == 4 } @$frames;
ok(!$frame, 'flow control - no window for next stream');

# window update

$s->h2_window(2);

$frames = $s->read(all => [{ length => 2 }]);
($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == 2 } @$frames;
is($frame->{length}, 2, 'window update');

# client refused stream

$s->h2_rst(4, 7);
$s->h2_window(2**16);

$frames = $s->read(all => [{ sid => 2, length => 1 }]);
push @$frames, @{ $s->read(all => [{ sid => 4, fin => 1 }], wait => 0.5) };

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == 2 } @$frames;
is($frame->{length}, 1, 'pushed response flow control');
is($frame->{flags}, 1, 'pushed response END_STREAM');

}

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == 4 } @$frames;
ok(!$frame, 'rst pushed stream');

TODO: {
local $TODO = 'not yet' if $t->read_file('nginx.conf') =~ /aio on/;

# priority

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/prio' });
$frames = $s->read(all => [{ length => 2**16 - 1 }, { sid => 4, fin => 4 }]);

$s->h2_priority(16, 2, 4);

$s->h2_window(2**17, 2);
$s->h2_window(2**17, 4);
$s->h2_window(2**17);

$frames = $s->read(all => [{ sid => 2, fin => 1 }, { sid => 4, fin => 1 }]);
my @data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "4 2", 'priority 1');

$s = Test::Nginx::HTTP2->new();
$sid = $s->new_stream({ path => '/prio' });
$frames = $s->read(all => [{ length => 2**16 - 1 }, { sid => 4, fin => 4 }]);

$s->h2_priority(16, 4, 2);

$s->h2_window(2**17, 2);
$s->h2_window(2**17, 4);
$s->h2_window(2**17);

$frames = $s->read(all => [{ sid => 2, fin => 1 }, { sid => 4, fin => 1 }]);
@data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "2 4", 'priority 2');

}

# http2_max_concurrent_pushes

$s = Test::Nginx::HTTP2->new(port(8082));
$sid = $s->new_stream({ headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'max_pushes', mode => 1 }]});
$frames = $s->read(all => [{ sid => $sid, fin => 1 },
	{ sid => 2, fin => 1 }, { sid => 4, fin => 1 }]);
push @$frames, @{ $s->read(all => [{ sid => 6, fin => 1 }], wait => 0.2) };
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 2, 'http2 max pushes lim');

$s = Test::Nginx::HTTP2->new(port(8082));
$s->h2_settings(0, 0x3 => 1);
$sid = $s->new_stream({ headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'max_pushes', mode => 1 }]});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }, { sid => 2, fin => 1 }]);
push @$frames, @{ $s->read(all => [{ sid => 4, fin => 1 }], wait => 0.2) };
is(grep({ $_->{type} eq "PUSH_PROMISE" } @$frames), 1, 'http2 max pushes 2');

# missing request header ':authority'

$s = Test::Nginx::HTTP2->new(port(8082));
$sid = $s->new_stream({ headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 }]});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 400, 'incomplete headers');

###############################################################################
