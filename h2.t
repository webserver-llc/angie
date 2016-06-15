#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol [RFC7540].

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2 qw/ :DEFAULT :frame :io /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/)->plan(137);

# Some systems return EINVAL on zero writev iovcnt per POSIX, while others not

$t->todo_alerts() if $^O eq 'darwin' or $^O eq 'netbsd';

$t->write_file_expand('nginx.conf', <<'EOF');

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

        location / {
            add_header X-Header X-Foo;
            add_header X-Sent-Foo $http_x_foo;
            add_header X-Referer $http_referer;
            return 200 'body';
        }
        location /t {
        }
        location /gzip.html {
            gzip on;
            gzip_min_length 0;
            gzip_vary on;
            alias %%TESTDIR%%/t2.html;
        }
        location /frame_size {
            http2_chunk_size 64k;
            alias %%TESTDIR%%/t1.html;
            output_buffers 2 1m;
        }
        location /chunk_size {
            http2_chunk_size 1;
            return 200 'body';
        }
        location /redirect {
            error_page 405 /;
            return 405;
        }
        location /return301 {
            return 301;
        }
        location /return301_absolute {
            return 301 text;
        }
        location /return301_relative {
            return 301 /;
        }
        location /charset {
            charset utf-8;
            return 200;
        }
    }

    server {
        listen       127.0.0.1:8085 http2;
        server_name  localhost;
        return 200   first;
    }

    server {
        listen       127.0.0.1:8085 http2;
        server_name  localhost2;
        return 200   second;
    }

    server {
        listen       127.0.0.1:8086 http2;
        server_name  localhost;

        http2_max_concurrent_streams 1;
    }

    server {
        listen       127.0.0.1:8089 http2;
        server_name  localhost;

        http2_recv_timeout 1s;
        client_header_timeout 1s;
        send_timeout 1s;
    }

    server {
        listen       127.0.0.1:8090 http2;
        server_name  localhost;

        http2_idle_timeout 1s;
        client_body_timeout 1s;

        location /proxy2/ {
            add_header X-Body $request_body;
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen       127.0.0.1:8091 http2;
        server_name  localhost;

        send_timeout 1s;
    }

    server {
        listen       127.0.0.1:8093 http2;
        server_name  localhost;

        client_header_timeout 1s;
        client_body_timeout 1s;

        location /proxy/ {
            proxy_pass http://127.0.0.1:8081/;
        }
    }
}

EOF

$t->run();

# file size is slightly beyond initial window size: 2**16 + 80 bytes

$t->write_file('t1.html',
	join('', map { sprintf "X%04dXXX", $_ } (1 .. 8202)));
$t->write_file('tbig.html',
	join('', map { sprintf "XX%06dXX", $_ } (1 .. 500000)));

$t->write_file('t2.html', 'SEE-THIS');

###############################################################################

# Upgrade mechanism

my $r = http(<<EOF);
GET / HTTP/1.1
Host: localhost
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

EOF

SKIP: {
skip 'no Upgrade-based negotiation', 2 if $r !~ m!HTTP/1.1 101!;

like($r, qr!Connection: Upgrade!, 'upgrade - connection');
like($r, qr!Upgrade: h2c!, 'upgrade - token');

}

# SETTINGS

my $sess = new_session(8080, pure => 1);
my $frames = h2_read($sess, all => [
	{ type => 'WINDOW_UPDATE' },
	{ type => 'SETTINGS'}
]);

my ($frame) = grep { $_->{type} eq 'WINDOW_UPDATE' } @$frames;
ok($frame, 'WINDOW_UPDATE frame');
is($frame->{flags}, 0, 'WINDOW_UPDATE zero flags');
is($frame->{sid}, 0, 'WINDOW_UPDATE zero sid');
is($frame->{length}, 4, 'WINDOW_UPDATE fixed length');

($frame) = grep { $_->{type} eq 'SETTINGS' } @$frames;
ok($frame, 'SETTINGS frame');
is($frame->{flags}, 0, 'SETTINGS flags');
is($frame->{sid}, 0, 'SETTINGS stream');

h2_settings($sess, 1);
h2_settings($sess, 0);

$frames = h2_read($sess, all => [{ type => 'SETTINGS' }]);

($frame) = grep { $_->{type} eq 'SETTINGS' } @$frames;
ok($frame, 'SETTINGS frame ack');
is($frame->{flags}, 1, 'SETTINGS flags ack');

# PING

h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" } @$frames;
ok($frame, 'PING frame');
is($frame->{value}, 'SEE-THIS', 'PING payload');
is($frame->{flags}, 1, 'PING flags ack');
is($frame->{sid}, 0, 'PING stream');

# timeouts

SKIP: {
skip 'long tests', 6 unless $ENV{TEST_NGINX_UNSAFE};

push my @sess, new_session(8089, pure => 1);
push @sess, new_session(8089, pure => 1);
h2_ping($sess[-1], 'SEE-THIS');
push @sess, new_session(8090, pure => 1);
push @sess, new_session(8090, pure => 1);
h2_ping($sess[-1], 'SEE-THIS');

select undef, undef, undef, 2.1;

$frames = h2_read(shift @sess, all => [{ type => "GOAWAY" }]);
($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'recv timeout - new connection GOAWAY');
is($frame->{code}, 1, 'recv timeout - new connection code');

$frames = h2_read(shift @sess, all => [{ type => "GOAWAY" }]);
($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
is($frame, undef, 'recv timeout - idle connection GOAWAY');

$frames = h2_read(shift @sess, all => [{ type => "GOAWAY" }]);
($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
is($frame, undef, 'idle timeout - new connection GOAWAY');

$frames = h2_read(shift @sess, all => [{ type => "GOAWAY" }]);
($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'idle timeout - idle connection GOAWAY');
is($frame->{code}, 0, 'idle timeout - idle connection code');

}

# GOAWAY

h2_goaway(new_session(), 0, 0, 5);
h2_goaway(new_session(), 0, 0, 5, 'foobar');
h2_goaway(new_session(), 0, 0, 5, 'foobar', split => [ 8, 8, 4 ]);

$sess = new_session();
h2_goaway($sess, 0, 0, 5);
h2_goaway($sess, 0, 0, 5);

$sess = new_session();
h2_goaway($sess, 0, 0, 5, 'foobar', len => 0);
$frames = h2_read($sess, all => [{ type => "GOAWAY" }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'GOAWAY invalid length - GOAWAY frame');
is($frame->{code}, 6, 'GOAWAY invalid length - GOAWAY FRAME_SIZE_ERROR');

# 6.8.  GOAWAY
#   An endpoint MUST treat a GOAWAY frame with a stream identifier other
#   than 0x0 as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.

TODO: {
local $TODO = 'not yet';

$sess = new_session();
h2_goaway($sess, 1, 0, 5, 'foobar');
$frames = h2_read($sess, all => [{ type => "GOAWAY" }], wait => 0.5);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'GOAWAY invalid stream - GOAWAY frame');
is($frame->{code}, 1, 'GOAWAY invalid stream - GOAWAY PROTOCOL_ERROR');

}

# client-initiated PUSH_PROMISE, just to ensure nothing went wrong
# N.B. other implementation returns zero code, which is not anyhow regulated

$sess = new_session();
raw_write($sess->{socket}, pack("x2C2xN", 4, 0x5, 1));
$frames = h2_read($sess, all => [{ type => "GOAWAY" }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'client-initiated PUSH_PROMISE - GOAWAY frame');
is($frame->{code}, 1, 'client-initiated PUSH_PROMISE - GOAWAY PROTOCOL_ERROR');

# GET

$sess = new_session();
my $sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
ok($frame, 'HEADERS frame');
is($frame->{sid}, $sid, 'HEADERS stream');
is($frame->{headers}->{':status'}, 200, 'HEADERS status');
is($frame->{headers}->{'x-header'}, 'X-Foo', 'HEADERS header');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
ok($frame, 'DATA frame');
is($frame->{length}, length 'body', 'DATA length');
is($frame->{data}, 'body', 'DATA payload');

# GET in the new stream on same connection

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{sid}, $sid, 'HEADERS stream 2');
is($frame->{headers}->{':status'}, 200, 'HEADERS status 2');
is($frame->{headers}->{'x-header'}, 'X-Foo', 'HEADERS header 2');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
ok($frame, 'DATA frame 2');
is($frame->{sid}, $sid, 'HEADERS stream 2');
is($frame->{length}, length 'body', 'DATA length 2');
is($frame->{data}, 'body', 'DATA payload 2');

# HEAD

$sess = new_session();
$sid = new_stream($sess, { method => 'HEAD' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 0x4 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{sid}, $sid, 'HEAD - HEADERS');
is($frame->{headers}->{':status'}, 200, 'HEAD - HEADERS status');
is($frame->{headers}->{'x-header'}, 'X-Foo', 'HEAD - HEADERS header');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame, undef, 'HEAD - no body');

# range filter

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/t1.html', mode => 1 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'range', value => 'bytes=10-19', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 206, 'range - HEADERS status');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{length}, 10, 'range - DATA length');
is($frame->{data}, '002XXXX000', 'range - DATA payload');

# http2_chunk_size=1

$sess = new_session();
$sid = new_stream($sess, { path => '/chunk_size' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

my @data = grep { $_->{type} eq "DATA" } @$frames;
is(@data, 4, 'chunk_size frames');
is(join(' ', map { $_->{data} } @data), 'b o d y', 'chunk_size data');
is(join(' ', map { $_->{flags} } @data), '0 0 0 1', 'chunk_size flags');

# CONTINUATION

$sess = new_session();
$sid = new_stream($sess, { continuation => 1, headers => [
	{ name => ':method', value => 'HEAD', mode => 1 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
h2_continue($sess, $sid, { continuation => 1, headers => [
	{ name => 'x-foo', value => 'X-Bar', mode => 2 }]});
h2_continue($sess, $sid, { headers => [
	{ name => 'referer', value => 'foo', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame, undef, 'CONTINUATION - fragment 1');

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-sent-foo'}, 'X-Bar', 'CONTINUATION - fragment 2');
is($frame->{headers}->{'x-referer'}, 'foo', 'CONTINUATION - fragment 3');

# CONTINUATION - in the middle of request header field

$sess = new_session();
$sid = new_stream($sess, { continuation => [ 2, 4, 1, 5 ], headers => [
	{ name => ':method', value => 'HEAD', mode => 1 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'CONTINUATION - in header field');

# CONTINUATION on a closed stream

h2_continue($sess, 1, { headers => [
	{ name => 'x-foo', value => 'X-Bar', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => 1, fin => 1 }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
is($frame->{type}, 'GOAWAY', 'GOAWAY - CONTINUATION closed stream');
is($frame->{code}, 1, 'GOAWAY - CONTINUATION closed stream - PROTOCOL_ERROR');

# frame padding

$sess = new_session();
$sid = new_stream($sess, { padding => 42, headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'padding - HEADERS status');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'padding - next stream');

# padding followed by CONTINUATION

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.9.11');

$sess = new_session();
$sid = new_stream($sess, { padding => 42, continuation => [ 2, 4, 1, 5 ],
	headers => [
	{ name => ':method', value => 'GET', mode => 1 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'padding - CONTINUATION');

}

# internal redirect

$sess = new_session();
$sid = new_stream($sess, { path => '/redirect' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 405, 'redirect - HEADERS');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
ok($frame, 'redirect - DATA');
is($frame->{data}, 'body', 'redirect - DATA payload');

# return 301 with absolute URI

$sess = new_session();
$sid = new_stream($sess, { path => '/return301_absolute' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 301, 'return 301 absolute - status');
is($frame->{headers}->{'location'}, 'text', 'return 301 absolute - location');

# return 301 with relative URI

$sess = new_session();
$sid = new_stream($sess, { path => '/return301_relative' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 301, 'return 301 relative - status');
is($frame->{headers}->{'location'}, 'http://localhost:8080/',
	'return 301 relative - location');

# return 301 with relative URI and ':authority' request header field

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/return301_relative', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 301,
	'return 301 relative - authority - status');
is($frame->{headers}->{'location'}, 'http://localhost:8080/',
	'return 301 relative - authority - location');

# return 301 with relative URI and 'host' request header field

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/return301_relative', mode => 2 },
	{ name => 'host', value => 'localhost', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 301,
	'return 301 relative - host - status');
is($frame->{headers}->{'location'}, 'http://localhost:8080/',
	'return 301 relative - host - location');

# virtual host

$sess = new_session(8085);
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => 'host', value => 'localhost', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'virtual host - host - status');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'first', 'virtual host - host - DATA');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'virtual host - authority - status');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'first', 'virtual host - authority - DATA');

# virtual host - second

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => 'host', value => 'localhost2', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'virtual host 2 - host - status');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'second', 'virtual host 2 - host - DATA');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost2', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'virtual host 2 - authority - status');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'second', 'virtual host 2 - authority - DATA');

# gzip tests for internal nginx version

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/gzip.html' },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'accept-encoding', value => 'gzip' }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'content-encoding'}, 'gzip', 'gzip - encoding');
is($frame->{headers}->{'vary'}, 'Accept-Encoding', 'gzip - vary');

($frame) = grep { $_->{type} eq "DATA" } @$frames;
gunzip_like($frame->{data}, qr/^SEE-THIS\Z/, 'gzip - DATA');

# charset

$sess = new_session();
$sid = new_stream($sess, { path => '/charset' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'content-type'}, 'text/plain; charset=utf-8', 'charset');

# partial request header frame received (field split),
# the rest of frame is received after client header timeout

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.9.12');

$sess = new_session(8093);
$sid = new_stream($sess, { path => '/t2.html', split => [35],
	split_delay => 2.1 });
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

($frame) = grep { $_->{type} eq "RST_STREAM" } @$frames;
ok($frame, 'client header timeout');
is($frame->{code}, 1, 'client header timeout - protocol error');

}

h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" && $_->{flags} & 0x1 } @$frames;
ok($frame, 'client header timeout - PING');

# partial request body data frame received, the rest is after body timeout

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.9.12');

$sess = new_session(8093);
$sid = new_stream($sess, { path => '/proxy/t2.html', body_more => 1 });
h2_body($sess, 'TEST', { split => [10], split_delay => 2.1 });
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

($frame) = grep { $_->{type} eq "RST_STREAM" } @$frames;
ok($frame, 'client body timeout');
is($frame->{code}, 1, 'client body timeout - protocol error');

}

h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" && $_->{flags} & 0x1 } @$frames;
ok($frame, 'client body timeout - PING');


# proxied request with logging pristine request header field (e.g., referer)

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET' },
	{ name => ':scheme', value => 'http' },
	{ name => ':path', value => '/proxy2/' },
	{ name => ':authority', value => 'localhost' },
	{ name => 'referer', value => 'foo' }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'proxy with logging request headers');

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
ok($frame->{headers}, 'proxy with logging request headers - next');

# initial window size, client side

# 6.9.2.  Initial Flow-Control Window Size
#   When an HTTP/2 connection is first established, new streams are
#   created with an initial flow-control window size of 65,535 octets.
#   The connection flow-control window is also 65,535 octets.

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

# with the default http2_chunk_size, data is divided into 8 data frames

@data = grep { $_->{type} eq "DATA" } @$frames;
my $lengths = join ' ', map { $_->{length} } @data;
is($lengths, '8192 8192 8192 8192 8192 8192 8192 8191',
	'iws - stream blocked on initial window size');

h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" && $_->{flags} & 0x1 } @$frames;
ok($frame, 'iws - PING not blocked');

h2_window($sess, 2**16, $sid);
$frames = h2_read($sess, wait => 0.2);
is(@$frames, 0, 'iws - updated stream window');

h2_window($sess, 2**16);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

@data = grep { $_->{type} eq "DATA" } @$frames;
my $sum = eval join '+', map { $_->{length} } @data;
is($sum, 81, 'iws - updated connection window');

# SETTINGS (initial window size, client side)

# 6.9.2.  Initial Flow-Control Window Size
#   Both endpoints can adjust the initial window size for new streams by
#   including a value for SETTINGS_INITIAL_WINDOW_SIZE in the SETTINGS
#   frame that forms part of the connection preface.  The connection
#   flow-control window can only be changed using WINDOW_UPDATE frames.

$sess = new_session();
h2_settings($sess, 0, 0x4 => 2**17);
h2_window($sess, 2**17);

$sid = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sum = eval join '+', map { $_->{length} } @data;
is($sum, 2**16 + 80, 'iws - increased');

# probe for negative available space in a flow control window

# 6.9.2.  Initial Flow-Control Window Size
#   A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available
#   space in a flow-control window to become negative.  A sender MUST
#   track the negative flow-control window and MUST NOT send new flow-
#   controlled frames until it receives WINDOW_UPDATE frames that cause
#   the flow-control window to become positive.

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

h2_window($sess, 1);
h2_settings($sess, 0, 0x4 => 42);
h2_window($sess, 1024, $sid);

$frames = h2_read($sess, all => [{ type => 'SETTINGS' }]);

($frame) = grep { $_->{type} eq 'SETTINGS' } @$frames;
ok($frame, 'negative window - SETTINGS frame ack');
is($frame->{flags}, 1, 'negative window - SETTINGS flags ack');

($frame) = grep { $_->{type} ne 'SETTINGS' } @$frames;
is($frame, undef, 'negative window - no data');

# predefined window size, minus new iws settings, minus window update

h2_window($sess, 2**16 - 1 - 42 - 1024, $sid);

$frames = h2_read($sess, wait => 0.2);
is(@$frames, 0, 'zero window - no data');

h2_window($sess, 1, $sid);

$frames = h2_read($sess, all => [{ sid => $sid, length => 1 }]);
is(@$frames, 1, 'positive window');

SKIP: {
skip 'failed connection', 2 unless @$frames;

is(@$frames[0]->{type}, 'DATA', 'positive window - data');
is(@$frames[0]->{length}, 1, 'positive window - data length');

}

# ask write handler in sending large response

$sid = new_stream($sess, { path => '/tbig.html' });

h2_window($sess, 2**30, $sid);
h2_window($sess, 2**30);

sleep 1;
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'large response - HEADERS');

@data = grep { $_->{type} eq "DATA" } @$frames;
$sum = eval join '+', map { $_->{length} } @data;
is($sum, 5000000, 'large response - DATA');

# Make sure http2 write handler doesn't break a connection.
# Some buggy systems tolerate ill-use of writev() triggered by write handler,
# while others, such as darwin and NetBSD, follow POSIX strictly, which causes
# a connection to close in nginx.  While this also breaks the 'no alerts' test,
# it doesn't suit well, because error.log is currently polluted with much more
# alerts due to other various bugs in ngx_http_v2_module.  We catch it here in
# a separate test as well to make it clear.

SKIP: {
skip 'tolerant operating system', 1 unless $^O eq 'darwin' or $^O eq 'netbsd';

TODO: {
local $TODO = 'not yet';

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'new stream after large response');

}

}

# write event send timeout

$sess = new_session(8091);
$sid = new_stream($sess, { path => '/tbig.html' });
h2_window($sess, 2**30, $sid);
h2_window($sess, 2**30);

select undef, undef, undef, 2.1;

h2_ping($sess, 'SEE-THIS');

$frames = h2_read($sess, all => [{ type => 'PING' }]);
ok(!grep ({ $_->{type} eq "PING" } @$frames), 'large response - send timeout');

# stream with large response queued on write - RST_STREAM handling

$sess = new_session();
$sid = new_stream($sess, { path => '/tbig.html' });

h2_window($sess, 2**30, $sid);
h2_window($sess, 2**30);

select undef, undef, undef, 0.4;

h2_rst($sess, $sid, 8);
h2_read($sess, all => [{ sid => $sid, fin => 1 }], wait => 0.2);

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{sid}, 3, 'large response - queued with RST_STREAM');

# SETTINGS_MAX_FRAME_SIZE

$sess = new_session();
$sid = new_stream($sess, { path => '/frame_size' });
h2_window($sess, 2**18, 1);
h2_window($sess, 2**18);

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
@data = grep { $_->{type} eq "DATA" } @$frames;
is($data[0]->{length}, 2**14, 'max frame size - default');

$sess = new_session();
h2_settings($sess, 0, 0x5 => 2**15);
$sid = new_stream($sess, { path => '/frame_size' });
h2_window($sess, 2**18, 1);
h2_window($sess, 2**18);

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
@data = grep { $_->{type} eq "DATA" } @$frames;
is($data[0]->{length}, 2**15, 'max frame size - custom');

# stream multiplexing + WINDOW_UPDATE

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sum = eval join '+', map { $_->{length} } @data;
is($sum, 2**16 - 1, 'multiple - stream1 data');

my $sid2 = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

@data = grep { $_->{type} eq "DATA" } @$frames;
is(@data, 0, 'multiple - stream2 no data');

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" && $_->{sid} == $sid } @$frames;
$sum = eval join '+', map { $_->{length} } @data;
is($sum, 81, 'multiple - stream1 remain data');

@data = grep { $_->{type} eq "DATA" && $_->{sid} == $sid2 } @$frames;
$sum = eval join '+', map { $_->{length} } @data;
is($sum, 2**16 + 80, 'multiple - stream2 full data');

# http2_max_concurrent_streams

$sess = new_session(8086, pure => 1);
$frames = h2_read($sess, all => [{ type => 'SETTINGS' }]);

($frame) = grep { $_->{type} eq 'SETTINGS' } @$frames;
is($frame->{3}, 1, 'http2_max_concurrent_streams SETTINGS');

h2_window($sess, 2**18);

$sid = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ sid => $sid, length => 2 ** 16 - 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid } @$frames;
is($frame->{headers}->{':status'}, 200, 'http2_max_concurrent_streams');

$sid2 = new_stream($sess, { path => '/t1.html' });
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid2 } @$frames;
isnt($frame->{headers}->{':status'}, 200, 'http2_max_concurrent_streams 2');

($frame) = grep { $_->{type} eq "RST_STREAM" && $_->{sid} == $sid2 } @$frames;
is($frame->{sid}, $sid2, 'http2_max_concurrent_streams RST_STREAM sid');
is($frame->{length}, 4, 'http2_max_concurrent_streams RST_STREAM length');
is($frame->{flags}, 0, 'http2_max_concurrent_streams RST_STREAM flags');
is($frame->{code}, 7, 'http2_max_concurrent_streams RST_STREAM code');

# properly skip header field that's not/never indexed from discarded streams

$sid2 = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET' },
	{ name => ':scheme', value => 'http' },
	{ name => ':path', value => '/', mode => 6 },
	{ name => ':authority', value => 'localhost' },
	{ name => 'x-foo', value => 'Foo', mode => 2 }]});
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

# also if split across writes

$sid2 = new_stream($sess, { split => [ 22 ], headers => [
	{ name => ':method', value => 'GET' },
	{ name => ':scheme', value => 'http' },
	{ name => ':path', value => '/', mode => 6 },
	{ name => ':authority', value => 'localhost' },
	{ name => 'x-bar', value => 'Bar', mode => 2 }]});
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

# also if split across frames

$sid2 = new_stream($sess, { continuation => [ 17 ], headers => [
	{ name => ':method', value => 'GET' },
	{ name => ':scheme', value => 'http' },
	{ name => ':path', value => '/', mode => 6 },
	{ name => ':authority', value => 'localhost' },
	{ name => 'x-baz', value => 'Baz', mode => 2 }]});
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

h2_window($sess, 2**16, $sid);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET' },
	{ name => ':scheme', value => 'http' },
	{ name => ':path', value => '/t2.html' },
	{ name => ':authority', value => 'localhost' },
# make sure that discarded streams updated dynamic table
	{ name => 'x-foo', value => 'Foo', mode => 0 },
	{ name => 'x-bar', value => 'Bar', mode => 0 },
	{ name => 'x-baz', value => 'Baz', mode => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid } @$frames;
is($frame->{headers}->{':status'}, 200, 'http2_max_concurrent_streams 3');


# some invalid cases below

# invalid connection preface

$sess = new_session(8080, preface => 'x' x 16, pure => 1);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'invalid preface - GOAWAY frame');
is($frame->{code}, 1, 'invalid preface - error code');

$sess = new_session(8080, preface => 'PRI * HTTP/2.0' . CRLF . CRLF . 'x' x 8,
	pure => 1);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'invalid preface 2 - GOAWAY frame');
is($frame->{code}, 1, 'invalid preface 2 - error code');

# GOAWAY on SYN_STREAM with even StreamID

$sess = new_session();
new_stream($sess, { path => '/' }, 2);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'even stream - GOAWAY frame');
is($frame->{code}, 1, 'even stream - error code');
is($frame->{last_sid}, 0, 'even stream - last stream');

# GOAWAY on SYN_STREAM with backward StreamID

# 5.1.1.  Stream Identifiers
#   The first use of a new stream identifier implicitly closes all
#   streams in the "idle" state <..> with a lower-valued stream identifier.

$sess = new_session();
$sid = new_stream($sess, { path => '/' }, 3);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid2 = new_stream($sess, { path => '/' }, 1);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'backward stream - GOAWAY frame');
is($frame->{code}, 1, 'backward stream - error code');
is($frame->{last_sid}, $sid, 'backward stream - last stream');

# GOAWAY on the second SYN_STREAM with same StreamID

$sess = new_session();
$sid = new_stream($sess, { path => '/' });
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid2 = new_stream($sess, { path => '/' }, $sid);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'dup stream - GOAWAY frame');
is($frame->{code}, 1, 'dup stream - error code');
is($frame->{last_sid}, $sid, 'dup stream - last stream');

# aborted stream with zero HEADERS payload followed by client connection close

new_stream(new_session(), { split => [ 9 ], abort => 1 });

# unknown frame type

$sess = new_session();
h2_unknown($sess, 'payload');
h2_ping($sess, 'SEE-THIS');
$frames = h2_read($sess, all => [{ type => 'PING' }]);

($frame) = grep { $_->{type} eq "PING" } @$frames;
is($frame->{value}, 'SEE-THIS', 'unknown frame type');

# GOAWAY - force closing a connection by server

$sid = new_stream($sess);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

# graceful shutdown with stream waiting on HEADERS payload

my $grace = new_session(8089);
new_stream($grace, { split => [ 9 ], abort => 1 });

# graceful shutdown with stream waiting on WINDOW_UPDATE

my $grace2 = new_session(8089);
$sid = new_stream($grace2, { path => '/t1.html' });
h2_read($grace2, all => [{ sid => $sid, length => 2**16 - 1 }]);

# graceful shutdown waiting on incomplete request body DATA frames

my $grace3 = new_session(8090);
$sid = new_stream($grace3, { path => '/proxy2/t2.html', body_more => 1 });
h2_body($grace3, 'TEST', { body_more => 1 });

# partial request body data frame with connection close after body timeout

my $grace4 = new_session(8093);
$sid = new_stream($grace4, { path => '/proxy/t2.html', body_more => 1 });
h2_body($grace4, 'TEST', { split => [ 12 ], abort => 1 });

select undef, undef, undef, 1.1;
undef $grace4;

$t->stop();

$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'GOAWAY on connection close');

###############################################################################

sub gunzip_like {
	my ($in, $re, $name) = @_;

	SKIP: {
		eval { require IO::Uncompress::Gunzip; };
		Test::More::skip(
			"IO::Uncompress::Gunzip not installed", 1) if $@;

		my $out;

		IO::Uncompress::Gunzip::gunzip(\$in => \$out);

		like($out, $re, $name);
	}
}

###############################################################################
