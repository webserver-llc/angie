#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol [RFC7540].

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2 proxy cache/)
	->has(qw/limit_conn rewrite realip shmem/)
	->has_daemon('openssl')->plan(170);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache    keys_zone=NAME:1m;
    limit_conn_zone  $binary_remote_addr  zone=conn:1m;
    output_buffers 2 16k;

    server {
        listen       127.0.0.1:8080 http2;
        listen       127.0.0.1:8081;
        listen       127.0.0.1:8082 proxy_protocol http2;
        listen       127.0.0.1:8084 http2 ssl;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            add_header X-Header X-Foo;
            add_header X-Sent-Foo $http_x_foo;
            add_header X-Referer $http_referer;
            return 200 'body';
        }
        location /t {
        }
        location /t3.html {
            limit_conn conn 1;
        }
        location /gzip.html {
            gzip on;
            gzip_min_length 0;
            alias %%TESTDIR%%/t2.html;
        }
        location /frame_size {
            http2_chunk_size 64k;
            alias %%TESTDIR%%/t1.html;
            output_buffers 2 1m;
        }
        location /pp {
            set_real_ip_from 127.0.0.1/32;
            real_ip_header proxy_protocol;
            alias %%TESTDIR%%/t2.html;
            add_header X-PP $remote_addr;
        }
        location /h2 {
            return 200 $http2;
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
        location /proxy/ {
            add_header X-UC-a $upstream_cookie_a;
            add_header X-UC-c $upstream_cookie_c;
            proxy_pass http://127.0.0.1:8083/;
            proxy_cache NAME;
            proxy_cache_valid 1m;
            proxy_set_header X-Cookie-a $cookie_a;
            proxy_set_header X-Cookie-c $cookie_c;
        }
        location /proxy2/ {
            add_header X-Body "$request_body";
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
        location /set-cookie {
            add_header Set-Cookie a=b;
            add_header Set-Cookie c=d;
            return 200;
        }
        location /cookie {
            add_header X-Cookie $http_cookie;
            add_header X-Cookie-a $cookie_a;
            add_header X-Cookie-c $cookie_c;
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
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config '$d/openssl.conf' -subj '/CN=$name/' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:8083');

# file size is slightly beyond initial window size: 2**16 + 80 bytes

$t->write_file('t1.html',
	join('', map { sprintf "X%04dXXX", $_ } (1 .. 8202)));
$t->write_file('tbig.html',
	join('', map { sprintf "X%04dXXX", $_ } (1 .. 8202)));

$t->write_file('t2.html', 'SEE-THIS');
$t->write_file('t3.html', 'SEE-THIS');

my %cframe = (
	0 => { name => 'DATA', value => \&data },
	1 => { name => 'HEADERS', value => \&headers },
#	2 => { name => 'PRIORITY', value => \&priority },
	3 => { name => 'RST_STREAM', value => \&rst_stream },
	4 => { name => 'SETTINGS', value => \&settings },
#	5 => { name => 'PUSH_PROIMSE', value => \&push_promise },
	6 => { name => 'PING', value => \&ping },
	7 => { name => 'GOAWAY', value => \&goaway },
	8 => { name => 'WINDOW_UPDATE', value => \&window_update },
#	9 => { name => 'CONTINUATION', value => \&continuation },
);

###############################################################################

# SETTINGS

my $sess = new_session();
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

# GET

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

# various HEADERS compression/encoding, see hpack() for mode details

# 6.1. Indexed Header Field Representation

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'indexed header field');

# 6.2.1. Literal Header Field with Incremental Indexing

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 1, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 1, huff => 0 },
	{ name => ':path', value => '/', mode => 1, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 1, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal with indexing');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 1, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 1, huff => 1 },
	{ name => ':path', value => '/', mode => 1, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 1, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal with indexing - huffman');

# 6.2.1. Literal Header Field with Incremental Indexing -- New Name

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 2, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 2, huff => 0 },
	{ name => ':path', value => '/', mode => 2, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 2, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal with indexing - new');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 2, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 2, huff => 1 },
	{ name => ':path', value => '/', mode => 2, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 2, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal with indexing - new huffman');

# 6.2.2. Literal Header Field without Indexing

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 3, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 3, huff => 0 },
	{ name => ':path', value => '/', mode => 3, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 3, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal without indexing');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 3, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 3, huff => 1 },
	{ name => ':path', value => '/', mode => 3, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 3, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal without indexing - huffman');

# 6.2.2. Literal Header Field without Indexing -- New Name

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 4, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 4, huff => 0 },
	{ name => ':path', value => '/', mode => 4, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 4, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal without indexing - new');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 4, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 4, huff => 1 },
	{ name => ':path', value => '/', mode => 4, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 4, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal without indexing - new huffman');

# 6.2.3. Literal Header Field Never Indexed

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 5, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 5, huff => 0 },
	{ name => ':path', value => '/', mode => 5, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 5, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal never indexed');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 5, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 5, huff => 1 },
	{ name => ':path', value => '/', mode => 5, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 5, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal never indexed - huffman');

# 6.2.2. Literal Header Field Never Indexed -- New Name

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 6, huff => 0 },
	{ name => ':scheme', value => 'http', mode => 6, huff => 0 },
	{ name => ':path', value => '/', mode => 6, huff => 0 },
	{ name => ':authority', value => 'localhost', mode => 6, huff => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal never indexed - new');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 6, huff => 1 },
	{ name => ':scheme', value => 'http', mode => 6, huff => 1 },
	{ name => ':path', value => '/', mode => 6, huff => 1 },
	{ name => ':authority', value => 'localhost', mode => 6, huff => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'literal never indexed - new huffman');

# reuse literal with indexing

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'referer', value => 'foo', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-referer'}, 'foo', 'value with indexing - new');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 0 },
	{ name => 'referer', value => 'foo', mode => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-referer'}, 'foo', 'value with indexing - indexed');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 0 },
	{ name => 'x-foo', value => 'X-Bar', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-sent-foo'}, 'X-Bar', 'name with indexing - new');

# reuse literal with indexing - reused name

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 0 },
	{ name => 'x-foo', value => 'X-Bar', mode => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-sent-foo'}, 'X-Bar', 'name with indexing - indexed');

# 6.3.  Dynamic Table Size Update

# remove some indexed headers from the dynamic table
# by maintaining dynamic table space only for index 0
# 'x-foo' has index 0, and 'referer' has index 1

$sid = new_stream($sess, { table_size => 61, headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => 'x-foo', value => 'X-Bar', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
isnt($frame, undef, 'updated table size - remaining index');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'referer', value => 'foo', mode => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame, undef, 'invalid index');

# 5.4.1.  Connection Error Handling
#   An endpoint that encounters a connection error SHOULD first send a
#   GOAWAY frame <..>

TODO: {
local $TODO = 'not yet';

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'invalid index - GOAWAY');

}

h2_ping($sess, 'SEE-THIS');
is(@{h2_read($sess, all => [{ type => 'PING' }])}, 0, 'invalid index - PING');
is($sess->{socket}->connected, undef, 'invalid index - connection close');

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

# GET with PROXY protocol

my $proxy = 'PROXY TCP4 192.0.2.1 192.0.2.2 1234 5678' . CRLF;
$sess = new_session(8082, proxy => $proxy);
$sid = new_stream($sess, { path => '/pp' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
ok($frame, 'PROXY HEADERS frame');
is($frame->{headers}->{'x-pp'}, '192.0.2.1', 'PROXY remote addr');

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

# $http2

$sess = new_session();
$sid = new_stream($sess, { path => '/h2' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'h2c', 'http variable - h2c');

# SSL/TLS connection, NPN

SKIP: {
eval { IO::Socket::SSL->can_npn() or die; };
skip 'OpenSSL NPN support required', 1 if $@;

$sess = new_session(8084, SSL => 1, npn => 'h2');
$sid = new_stream($sess, { path => '/h2' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'h2', 'http variable - npn');

}

# SSL/TLS connection, ALPN

SKIP: {
eval { IO::Socket::SSL->can_alpn() or die; };
skip 'OpenSSL ALPN support required', 1 if $@;

$sess = new_session(8084, SSL => 1, alpn => 'h2');
$sid = new_stream($sess, { path => '/h2' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'h2', 'http variable - alpn');

}

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

# request header field with multiple values

# 8.1.2.5.  Compressing the Cookie Header Field
#   To allow for better compression efficiency, the Cookie header field
#   MAY be split into separate header fields <..>.

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/cookie', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'cookie', value => 'a=b', mode => 2},
	{ name => 'cookie', value => 'c=d', mode => 2}]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-cookie-a'}, 'b',
	'multiple request header fields - cookie');
is($frame->{headers}->{'x-cookie-c'}, 'd',
	'multiple request header fields - cookie 2');
is($frame->{headers}->{'x-cookie'}, 'a=b; c=d',
	'multiple request header fields - semi-colon');

# request header field with multiple values to HTTP backend

# 8.1.2.5.  Compressing the Cookie Header Field
#   these MUST be concatenated into a single octet string
#   using the two-octet delimiter of 0x3B, 0x20 (the ASCII string "; ")
#   before being passed into a non-HTTP/2 context, such as an HTTP/1.1
#   connection <..>

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/proxy/cookie', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'cookie', value => 'a=b', mode => 2 },
	{ name => 'cookie', value => 'c=d', mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-sent-cookie'}, 'a=b; c=d',
	'multiple request header fields proxied - semi-colon');
is($frame->{headers}->{'x-sent-cookie2'}, '',
	'multiple request header fields proxied - dublicate cookie');
is($frame->{headers}->{'x-sent-cookie-a'}, 'b',
	'multiple request header fields proxied - cookie 1');
is($frame->{headers}->{'x-sent-cookie-c'}, 'd',
	'multiple request header fields proxied - cookie 2');

# response header field with multiple values

$sess = new_session();
$sid = new_stream($sess, { path => '/set-cookie' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'set-cookie'}[0], 'a=b',
	'multiple response header fields - cookie');
is($frame->{headers}->{'set-cookie'}[1], 'c=d',
	'multiple response header fields - cookie 2');

# response header field with multiple values from HTTP backend

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy/set-cookie' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'set-cookie'}[0], 'a=b',
	'multiple response header proxied - cookie');
is($frame->{headers}->{'set-cookie'}[1], 'c=d',
	'multiple response header proxied - cookie 2');
is($frame->{headers}->{'x-uc-a'}, 'b',
	'multiple response header proxied - upstream cookie');
is($frame->{headers}->{'x-uc-c'}, 'd',
	'multiple response header proxied - upstream cookie 2');

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
is($frame->{headers}->{'location'}, 'http://127.0.0.1:8080/',
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

($frame) = grep { $_->{type} eq "DATA" } @$frames;
gunzip_like($frame->{data}, qr/^SEE-THIS\Z/, 'gzip - DATA');

# simple proxy cache test

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t2.html?2' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'proxy cache');

my $etag = $frame->{headers}->{'etag'};

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{length}, length 'SEE-THIS', 'proxy cache - DATA');
is($frame->{data}, 'SEE-THIS', 'proxy cache - DATA payload');

$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/proxy2/t2.html?2' },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'if-none-match', value => $etag }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 304, 'proxy cache conditional');

# HEADERS could be received with fin, followed by DATA

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t2.html', method => 'HEAD' });

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
push @$frames, $_ for @{h2_read($sess, all => [{ sid => $sid }])};
ok(!grep ({ $_->{type} eq "DATA" } @$frames), 'proxy cache HEAD - no body');

# HEAD on empty cache with proxy_buffering off

$sess = new_session();
$sid = new_stream($sess,
	{ path => '/proxy_buffering_off/t2.html?1', method => 'HEAD' });

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
push @$frames, $_ for @{h2_read($sess, all => [{ sid => $sid }])};
ok(!grep ({ $_->{type} eq "DATA" } @$frames),
	'proxy cache HEAD buffering off - no body');

# request body (uses proxied response)

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t2.html', body => 'TEST' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-body'}, 'TEST', 'request body');

# request body with padding (uses proxied response)

$sess = new_session();
$sid = new_stream($sess,
	{ path => '/proxy2/t2.html', body => 'TEST', body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-body'}, 'TEST', 'request body with padding');

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'request body with padding - next');

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
$frames = h2_read($sess);
is(@$frames, 0, 'iws - updated stream window');

h2_window($sess, 2**16);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

# with the default output_buffers, the remain data would be split
# on buffers boundary into separate data frames

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

$frames = h2_read($sess);
is(@$frames, 0, 'zero window - no data');

h2_window($sess, 1, $sid);

$frames = h2_read($sess, all => [{ sid => $sid, length => 1 }]);
is(@$frames, 1, 'positive window');
is(@$frames[0]->{type}, 'DATA', 'positive window - data');
is(@$frames[0]->{length}, 1, 'positive window - data length');

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

# stream muliplexing + PRIORITY frames

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_priority($sess, 0, $sid);
h2_priority($sess, 255, $sid2);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "$sid2 $sid", 'weight - PRIORITY 1');

# and vice versa

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_priority($sess, 255, $sid);
h2_priority($sess, 0, $sid2);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "$sid $sid2", 'weight - PRIORITY 2');

# stream muliplexing + HEADERS PRIORITY flag

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html', prio => 0 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', prio => 255 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
my $sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'weight - HEADERS PRIORITY 1');

# and vice versa

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html', prio => 255 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', prio => 0 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'weight - HEADERS PRIORITY 2');

# 5.3.1.  Stream Dependencies

# PRIORITY frame

$sess = new_session();

h2_priority($sess, 16, 3, 0);
h2_priority($sess, 16, 1, 3);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'dependency - PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 1);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'dependency - PRIORITY 2');

# HEADERS PRIORITY flag, reprioritize prior PRIORITY frame records

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 0);

$sid = new_stream($sess, { path => '/t1.html', dep => 3 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'dependency - HEADERS PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 0);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', dep => 1 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'dependency - HEADERS PRIORITY 2');

# PRIORITY frame, weighted dependencies

$sess = new_session();

h2_priority($sess, 16, 5, 0);
h2_priority($sess, 255, 1, 5);
h2_priority($sess, 0, 3, 5);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

my $sid3 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**16, 1);
h2_window($sess, 2**16, 3);
h2_window($sess, 2**16, 5);
h2_window($sess, 2**16);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid3 $sid $sid2", 'weighted dependency - PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 5, 0);
h2_priority($sess, 0, 1, 5);
h2_priority($sess, 255, 3, 5);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

$sid3 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**16, 1);
h2_window($sess, 2**16, 3);
h2_window($sess, 2**16, 5);
h2_window($sess, 2**16);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid3 $sid2 $sid", 'weighted dependency - PRIORITY 2');

# limit_conn

$sess = new_session();
h2_settings($sess, 0, 0x4 => 1);

$sid = new_stream($sess, { path => '/t3.html' });
$frames = h2_read($sess, all => [{ sid => $sid, length => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid } @$frames;
is($frame->{headers}->{':status'}, 200, 'limit_conn first stream');

$sid2 = new_stream($sess, { path => '/t3.html' });
$frames = h2_read($sess, all => [{ sid => $sid2, fin => 0 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid2 } @$frames;
is($frame->{headers}->{':status'}, 503, 'limit_conn rejected');

h2_settings($sess, 0, 0x4 => 2**16);

h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

# limit_conn + client's RST_STREAM

$sess = new_session();
h2_settings($sess, 0, 0x4 => 1);

$sid = new_stream($sess, { path => '/t3.html' });
$frames = h2_read($sess, all => [{ sid => $sid, length => 1 }]);
h2_rst($sess, $sid, 5);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid } @$frames;
is($frame->{headers}->{':status'}, 200, 'RST_STREAM 1');

$sid2 = new_stream($sess, { path => '/t3.html' });
$frames = h2_read($sess, all => [{ sid => $sid2, fin => 0 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid2 } @$frames;
is($frame->{headers}->{':status'}, 200, 'RST_STREAM 2');

# http2_max_concurrent_streams

$sess = new_session(8086);
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

h2_window($sess, 2**16, $sid);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid = new_stream($sess, { path => '/t2.html' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid } @$frames;
is($frame->{headers}->{':status'}, 200, 'http2_max_concurrent_streams 3');


# some invalid cases below

# ensure that request header field value with newline doesn't get split
#
# 10.3.  Intermediary Encapsulation Attacks
#   Any request or response that contains a character not permitted
#   in a header field value MUST be treated as malformed.

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/proxy2/', mode => 1 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'x-foo', value => "x-bar\r\nreferer:see-this", mode => 2 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

# 10.3.  Intermediary Encapsulation Attacks
#   An intermediary therefore cannot translate an HTTP/2 request or response
#   containing an invalid field name into an HTTP/1.1 message.

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
isnt($frame->{headers}->{'x-referer'}, 'see-this', 'newline in request header');

# 8.1.2.6.  Malformed Requests and Responses
#   For malformed requests, a server MAY send an HTTP response prior to
#   closing or resetting the stream.

is($frame->{headers}->{':status'}, 400, 'newline in request header - status');

# 8.1.2.6.  Malformed Requests and Responses
#   Malformed requests or responses that are detected MUST be treated
#   as a stream error (Section 5.4.2) of type PROTOCOL_ERROR.

TODO: {
local $TODO = 'not yet';

($frame) = grep { $_->{type} eq "RST_STREAM" } @$frames;
is($frame->{sid}, $sid, 'newline in request header - RST_STREAM sid');
is($frame->{length}, 4, 'newline in request header - RST_STREAM length');
is($frame->{flags}, 0, 'newline in request header - RST_STREAM flags');
is($frame->{code}, 1, 'newline in request header - RST_STREAM code');

}

# GOAWAY on SYN_STREAM with even StreamID

TODO: {
local $TODO = 'not yet';

$sess = new_session();
new_stream($sess, { path => '/' }, 2);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'even stream - GOAWAY frame');
is($frame->{code}, 1, 'even stream - error code');
is($frame->{last_sid}, 0, 'even stream - last stream');

}

# GOAWAY on SYN_STREAM with backward StreamID

# 5.1.1.  Stream Identifiers
#   The first use of a new stream identifier implicitly closes all
#   streams in the "idle" state <..> with a lower-valued stream identifier.

TODO: {
local $TODO = 'not yet';

$sess = new_session();
$sid = new_stream($sess, { path => '/' }, 3);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid2 = new_stream($sess, { path => '/' }, 1);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'backward stream - GOAWAY frame');
is($frame->{code}, 1, 'backward stream - error code');
is($frame->{last_sid}, $sid, 'backward stream - last stream');

}

# GOAWAY on the second SYN_STREAM with same StreamID

TODO: {
local $TODO = 'not yet';

$sess = new_session();
$sid = new_stream($sess, { path => '/' });
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

$sid2 = new_stream($sess, { path => '/' }, $sid);
$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'dup stream - GOAWAY frame');
is($frame->{code}, 1, 'dup stream - error code');
is($frame->{last_sid}, $sid, 'dup stream - last stream');

}

# missing mandatory request header ':scheme'

TODO: {
local $TODO = 'not yet';

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => 'localhost', mode => 1 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 400, 'incomplete headers');

}

# empty request header ':authority'

$sess = new_session();
$sid = new_stream($sess, { headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/', mode => 0 },
	{ name => ':authority', value => '', mode => 0 }]});
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 400, 'empty authority');

# GOAWAY - force closing a connection by server

$sid = new_stream($sess, { path => 't1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$t->stop();

TODO: {
local $TODO = 'not yet';

$frames = h2_read($sess, all => [{ type => 'GOAWAY' }]);

($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
ok($frame, 'GOAWAY on connection close');

}

###############################################################################

sub h2_ping {
	my ($sess, $payload) = @_;

	raw_write($sess->{socket}, pack("x2C2x5a8", 8, 0x6, $payload));
}

sub h2_rst {
	my ($sess, $stream, $error) = @_;

	raw_write($sess->{socket}, pack("x2C2xNN", 4, 0x3, $stream, $error));
}

sub h2_priority {
	my ($sess, $w, $stream, $dep) = @_;

	$stream = 0 unless defined $stream;
	$dep = 0 unless defined $dep;
	raw_write($sess->{socket}, pack("x2C2xNNC", 5, 0x2, $stream, $dep, $w));
}

sub h2_window {
	my ($sess, $win, $stream) = @_;

	$stream = 0 unless defined $stream;
	raw_write($sess->{socket}, pack("x2C2xNN", 4, 0x8, $stream, $win));
}

sub h2_settings {
	my ($sess, $ack, %extra) = @_;

	my $len = 6 * keys %extra;
	my $buf = pack_length($len) . pack "CCx4", 0x4, $ack ? 0x1 : 0x0;
	$buf .= join '', map { pack "nN", $_, $extra{$_} } keys %extra;
	raw_write($sess->{socket}, $buf);
}

sub h2_continue {
	my ($ctx, $stream, $uri) = @_;

	$uri->{h2_continue} = 1;
	return new_stream($ctx, $uri, $stream);
}

sub new_stream {
	my ($ctx, $uri, $stream) = @_;
	my ($input, $buf);
	my ($d, $status);

	my $host = $uri->{host} || '127.0.0.1:8080';
	my $method = $uri->{method} || 'GET';
	my $scheme = $uri->{scheme} || 'http';
	my $path = $uri->{path} || '/';
	my $headers = $uri->{headers};
	my $body = $uri->{body};
	my $prio = $uri->{prio};
	my $dep = $uri->{dep};

	my $pad = defined $uri->{padding} ? $uri->{padding} : 0;
	my $padlen = defined $uri->{padding} ? 1 : 0;
	my $bpad = defined $uri->{body_padding} ? $uri->{body_padding} : 0;
	my $bpadlen = defined $uri->{body_padding} ? 1 : 0;

	my $type = defined $uri->{h2_continue} ? 0x9 : 0x1;
	my $flags = defined $uri->{continuation} ? 0x0 : 0x4;
	$flags |= 0x1 unless defined $body;
	$flags |= 0x8 if $padlen;
	$flags |= 0x20 if defined $dep || defined $prio;

	if ($stream) {
		$ctx->{last_stream} = $stream;
	} else {
		$ctx->{last_stream} += 2;
	}

	$buf = pack("xxx");			# Length stub
	$buf .= pack("CC", $type, $flags);	# END_HEADERS
	$buf .= pack("N", $ctx->{last_stream});	# Stream-ID

	$dep = 0 if defined $prio and not defined $dep;
	$prio = 16 if defined $dep and not defined $prio;

	unless ($headers) {
		$input = hpack($ctx, ":method", $method);
		$input .= hpack($ctx, ":scheme", $scheme);
		$input .= hpack($ctx, ":path", $path);
		$input .= hpack($ctx, ":authority", $host);
		$input .= hpack($ctx, "content-length", length($body)) if $body;

	} else {
		$input = join '', map {
			hpack($ctx, $_->{name}, $_->{value},
			mode => $_->{mode}, huff => $_->{huff})
		} @$headers if $headers;
	}

	# 5.1.  Integer Representation

	sub intpack {
		my $d = shift;
		return pack('B8', '001' . sprintf("%5b", $d)) if $d < 31;

		my $o = '00111111';
		$d -= 31;
		while ($d >= 128) {
			$o .= sprintf("%8b", $d % 128 + 128);
			$d /= 128;
		}
		$o .= sprintf("%08b", $d);
		return pack('B*', $o);
	}

	$input = intpack($uri->{table_size}) . $input
		if defined $uri->{table_size};

	# set length, attach headers, padding, priority

	my $hlen = length($input) + $pad + $padlen;
	$hlen += 5 if $flags & 0x20;
	$buf |= pack_length($hlen);

	$buf .= pack 'C', $pad if $padlen;		# Pad Length?
	$buf .= pack 'NC', $dep, $prio if $flags & 0x20;
	$buf .= $input;
	$buf .= (pack 'C', 0) x $pad if $padlen;	# Padding

	if (defined $body) {
		$buf .= pack_length(length($body) + $bpad + $bpadlen);
		my $flags = $bpadlen ? 0x8 : 0x0;
		$buf .= pack 'CC', 0x0, 0x1 | $flags;	# DATA, END_STREAM
		$buf .= pack 'N', $ctx->{last_stream};
		$buf .= pack 'C', $bpad if $bpadlen;	# DATA Pad Length?
		$buf .= $body;
		$buf .= (pack 'C', 0) x $bpad if $bpadlen;	# DATA Padding
	}

	raw_write($ctx->{socket}, $buf);
	return $ctx->{last_stream};
}

sub h2_read {
	my ($sess, %extra) = @_;
	my (@got);
	my $s = $sess->{socket};
	my $buf = '';

	while (1) {
		$buf = raw_read($s, $buf, 9);
		last unless length $buf;

		my $length = unpack_length($buf);
		my $type = unpack('x3C', $buf);
		my $flags = unpack('x4C', $buf);

		my $stream = unpack "x5 B32", $buf;
		substr($stream, 0, 1) = 0;
		$stream = unpack("N", pack("B32", $stream));

		$buf = raw_read($s, $buf, $length + 9);
		last unless length $buf;

		$buf = substr($buf, 9);

		my $frame = $cframe{$type}{value}($sess, $buf, $length);
		$frame->{length} = $length;
		$frame->{type} = $cframe{$type}{name};
		$frame->{flags} = $flags;
		$frame->{sid} = $stream;
		push @got, $frame;

		$buf = substr($buf, $length);

		last unless test_fin($got[-1], $extra{all});
	};
	return \@got;
}

sub test_fin {
	my ($frame, $all) = @_;
	my @test = @{$all};

	# wait for the specified DATA length

	for (@test) {
		if ($_->{length} && $frame->{type} eq 'DATA') {
			# check also for StreamID if needed

			if (!$_->{sid} || $_->{sid} == $frame->{sid}) {
				$_->{length} -= $frame->{length};
			}
		}
	}
	@test = grep { !(defined $_->{length} && $_->{length} == 0) } @test;

	# wait for the fin flag

	@test = grep { !(defined $_->{fin}
		&& $_->{sid} == $frame->{sid} && $_->{fin} & $frame->{flags})
	} @test if defined $frame->{flags};

	# wait for the specified frame

	@test = grep { !($_->{type} && $_->{type} eq $frame->{type}) } @test;

	@{$all} = @test;
}

sub headers {
	my ($ctx, $buf, $len) = @_;
	return { headers => hunpack($ctx, $buf, $len) };
}

sub data {
	my ($ctx, $buf, $len) = @_;
	return { data => substr($buf, 0, $len) };
}

sub settings {
	my ($ctx, $buf, $len) = @_;
	my %payload;
	my $skip = 0;

	for (1 .. $len / 6) {
		my $id = hex unpack "\@$skip n", $buf; $skip += 2;
		$payload{$id} = unpack "\@$skip N", $buf; $skip += 4;
	}
	return \%payload;
}

sub ping {
	my ($ctx, $buf, $len) = @_;
	return { value => unpack "A$len", $buf };
}

sub rst_stream {
	my ($ctx, $buf, $len) = @_;
	return { code => unpack "N", $buf };
}

sub goaway {
	my ($ctx, $buf, $len) = @_;
	my %payload;

	my $stream = unpack "B32", $buf;
	substr($stream, 0, 1) = 0;
	$stream = unpack("N", pack("B32", $stream));
	$payload{last_sid} = $stream;

	$len -= 4;
	$payload{code} = unpack "x4 N", $buf;
	$payload{debug} = unpack "x8 A$len", $buf;
	return \%payload;
}

sub window_update {
	my ($ctx, $buf, $len) = @_;
	my $value = unpack "B32", $buf;
	substr($value, 0, 1) = 0;
	return { wdelta => unpack("N", pack("B32", $value)) };
}

sub pack_length {
	pack 'c3', unpack 'xc3', pack 'N', $_[0];
}

sub unpack_length {
	unpack 'N', pack 'xc3', unpack 'c3', $_[0];
}

sub raw_read {
	my ($s, $buf, $len) = @_;
	my $got = '';

	while (length($buf) < $len && IO::Select->new($s)->can_read(1))  {
		$s->sysread($got, 16384) or last;
		log_in($got);
		$buf .= $got;
	}
	return $buf;
}

sub raw_write {
	my ($s, $message) = @_;

	local $SIG{PIPE} = 'IGNORE';

	while (IO::Select->new($s)->can_write(0.4)) {
		log_out($message);
		my $n = $s->syswrite($message);
		last unless $n;
		$message = substr($message, $n);
		last unless length $message;
	}
}

sub new_session {
	my ($port, %extra) = @_;
	my ($s);

	$s = new_socket($port, %extra);

	if ($extra{proxy}) {
		raw_write($s, $extra{proxy});
	}

	# preface

	raw_write($s, 'PRI * HTTP/2.0' . CRLF . CRLF . 'SM' . CRLF . CRLF);

	return { socket => $s, last_stream => -1,
		dynamic_encode => [ static_table() ],
		dynamic_decode => [ static_table() ],
		static_table_size => scalar @{[static_table()]} };
}

sub new_socket {
	my ($port, %extra) = @_;
	my $npn = $extra{'npn'};
	my $alpn = $extra{'alpn'};
	my $s;

	$port = 8080 unless defined $port;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(2);
		$s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => "127.0.0.1:$port",
		);
		IO::Socket::SSL->start_SSL($s,
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_npn_protocols => $npn ? [ $npn ] : undef,
			SSL_alpn_protocols => $alpn ? [ $alpn ] : undef,
			SSL_error_trap => sub { die $_[1] }
		) if $extra{'SSL'};
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

sub static_table {
	[ '',			''		], # unused
	[ ':authority',		''		],
	[ ':method',		'GET'		],
	[ ':method',		'POST'		],
	[ ':path',		'/'		],
	[ ':path',		'/index.html'	],
	[ ':scheme',		'http'		],
	[ ':scheme',		'https'		],
	[ ':status',		'200'		],
	[ ':status',		'204'		],
	[ ':status',		'206'		],
	[ ':status',		'304'		],
	[ ':status',		'400'		],
	[ ':status',		'404'		],
	[ ':status',		'500'		],
	[ 'accept-charset',	''		],
	[ 'accept-encoding',	'gzip, deflate'	],
	[ 'accept-language',	''		],
	[ 'accept-ranges',	''		],
	[ 'accept',		''		],
	[ 'access-control-allow-origin',
				''		],
	[ 'age',		''		],
	[ 'allow',		''		],
	[ 'authorization', 	''		],
	[ 'cache-control', 	''		],
	[ 'content-disposition',
				''		],
	[ 'content-encoding',	''		],
	[ 'content-language',	''		],
	[ 'content-length',	''		],
	[ 'content-location',	''		],
	[ 'content-range',	''		],
	[ 'content-type',	''		],
	[ 'cookie',		''		],
	[ 'date',		''		],
	[ 'etag',		''		],
	[ 'expect',		''		],
	[ 'expires',		''		],
	[ 'from',		''		],
	[ 'host',		''		],
	[ 'if-match',		''		],
	[ 'if-modified-since',	''		],
	[ 'if-none-match',	''		],
	[ 'if-range',		''		],
	[ 'if-unmodified-since',
				''		],
	[ 'last-modified',	''		],
	[ 'link',		''		],
	[ 'location',		''		],
	[ 'max-forwards',	''		],
	[ 'proxy-authenticate',	''		],
	[ 'proxy-authorization',
				''		],
	[ 'range',		''		],
	[ 'referer',		''		],
	[ 'refresh',		''		],
	[ 'retry-after',	''		],
	[ 'server',		''		],
	[ 'set-cookie',		''		],
	[ 'strict-transport-security',
				''		],
	[ 'transfer-encoding',	''		],
	[ 'user-agent',		''		],
	[ 'vary',		''		],
	[ 'via',		''		],
	[ 'www-authenticate',	''		],
}

sub hpack {
	my ($ctx, $name, $value, %extra) = @_;
	my $table = $ctx->{dynamic_encode};
	my $mode = defined $extra{mode} ? $extra{mode} : 1;
	my $huff = $extra{huff};

	my ($index, $buf) = 0;

	# 6.1.  Indexed Header Field Representation

	if ($mode == 0) {
		++$index until $index > $#$table
			or $table->[$index][0] eq $name
			and $table->[$index][1] eq $value;
		$buf = pack('B*', '1' . sprintf("%7b", $index));
	}

	# 6.2.1.  Literal Header Field with Incremental Indexing

	if ($mode == 1) {
		splice @$table, $ctx->{static_table_size}, 0, [ $name, $value ];

		++$index until $index > $#$table
			or $table->[$index][0] eq $name;
		my $value = $huff ? huff($value) : $value;

		$buf = pack('B*', '01' . sprintf("%6b", $index)
			. ($huff ? '1' : '0') . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	# 6.2.1.  Literal Header Field with Incremental Indexing -- New Name

	if ($mode == 2) {
		splice @$table, $ctx->{static_table_size}, 0, [ $name, $value ];

		my $name = $huff ? huff($name) : $name;
		my $value = $huff ? huff($value) : $value;
		my $hbit = ($huff ? '1' : '0');

		$buf = pack('B*', '01000000');
		$buf .= pack('B*', $hbit . sprintf("%7b", length($name)));
		$buf .= $name;
		$buf .= pack('B*', $hbit . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	# 6.2.2.  Literal Header Field without Indexing

	if ($mode == 3) {
		++$index until $index > $#$table
			or $table->[$index][0] eq $name;
		my $value = $huff ? huff($value) : $value;

		$buf = pack('B*', '0000' . sprintf("%4b", $index)
			. ($huff ? '1' : '0') . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	# 6.2.2.  Literal Header Field without Indexing -- New Name

	if ($mode == 4) {
		my $name = $huff ? huff($name) : $name;
		my $value = $huff ? huff($value) : $value;
		my $hbit = ($huff ? '1' : '0');

		$buf = pack('B*', '00000000');
		$buf .= pack('B*', $hbit . sprintf("%7b", length($name)));
		$buf .= $name;
		$buf .= pack('B*', $hbit . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	# 6.2.3.  Literal Header Field Never Indexed

	if ($mode == 5) {
		++$index until $index > $#$table
			or $table->[$index][0] eq $name;
		my $value = $huff ? huff($value) : $value;

		$buf = pack('B*', '0001' . sprintf("%4b", $index)
			. ($huff ? '1' : '0') . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	# 6.2.3.  Literal Header Field Never Indexed -- New Name

	if ($mode == 6) {
		my $name = $huff ? huff($name) : $name;
		my $value = $huff ? huff($value) : $value;
		my $hbit = ($huff ? '1' : '0');

		$buf = pack('B*', '00010000');
		$buf .= pack('B*', $hbit . sprintf("%7b", length($name)));
		$buf .= $name;
		$buf .= pack('B*', $hbit . sprintf("%7b", length($value)));
		$buf .= $value;
	}

	return $buf;
}

sub hunpack {
	my ($ctx, $data, $length) = @_;
	my $table = $ctx->{dynamic_decode};
	my %headers;
	my $skip = 0;
	my ($name, $value);

	sub index {
		my ($b, $i) = @_;
		unpack("C", pack("B8", '0' x $i . substr($b, $i, 8 - $i)));
	}

	sub field {
		my ($b, $s) = @_;
		my $len = unpack("\@$s B8", $b);
		my $huff = substr($len, 0, 1) ? 1 : 0;
		$len = unpack("C", pack("B8", '0' . substr($len, 1, 8)));
		$s++;

		my $field = substr($b, $s, $len);
		$field = $huff ? dehuff($field) : $field;
		$s += $len;
		return ($field, $s);
	}

	sub add {
		my ($h, $n, $v) = @_;
		return $h->{$n} = $v unless exists $h->{$n};
		$h->{$n} = [ $h->{$n} ];
		push @{$h->{$n}}, $v;
	}

	while ($skip < $length) {
		my $ib = unpack("\@$skip B8", $data);

		if (substr($ib, 0, 1) eq '1') {
			my $index = &index($ib, 1);
			add(\%headers,
				$table->[$index][0], $table->[$index][1]);
			$skip += 1;
			next;
		}

		if (substr($ib, 0, 2) eq '01') {
			$name = $table->[&index($ib, 2)][0];
			$skip++;

			($name, $skip) = field($data, $skip) unless $name;
			($value, $skip) = field($data, $skip);

			splice @$table,
				$ctx->{static_table_size}, 0, [ $name, $value ];
			add(\%headers, $name, $value);
			next;
		}

		if (substr($ib, 0, 4) eq '0000') {
			$name = $table->[&index($ib, 4)][0];
			$skip++;

			($name, $skip) = field($data, $skip) unless $name;
			($value, $skip) = field($data, $skip);

			add(\%headers, $name, $value);
			next;
		}
	}

	return \%headers;
}

sub huff_code { scalar {
	pack('C', 0)	=> '1111111111000',
	pack('C', 1)	=> '11111111111111111011000',
	pack('C', 2)	=> '1111111111111111111111100010',
	pack('C', 3)	=> '1111111111111111111111100011',
	pack('C', 4)	=> '1111111111111111111111100100',
	pack('C', 5)	=> '1111111111111111111111100101',
	pack('C', 6)	=> '1111111111111111111111100110',
	pack('C', 7)	=> '1111111111111111111111100111',
	pack('C', 8)	=> '1111111111111111111111101000',
	pack('C', 9)	=> '111111111111111111101010',
	pack('C', 10)	=> '111111111111111111111111111100',
	pack('C', 11)	=> '1111111111111111111111101001',
	pack('C', 12)	=> '1111111111111111111111101010',
	pack('C', 13)	=> '111111111111111111111111111101',
	pack('C', 14)	=> '1111111111111111111111101011',
	pack('C', 15)	=> '1111111111111111111111101100',
	pack('C', 16)	=> '1111111111111111111111101101',
	pack('C', 17)	=> '1111111111111111111111101110',
	pack('C', 18)	=> '1111111111111111111111101111',
	pack('C', 19)	=> '1111111111111111111111110000',
	pack('C', 20)	=> '1111111111111111111111110001',
	pack('C', 21)	=> '1111111111111111111111110010',
	pack('C', 22)	=> '111111111111111111111111111110',
	pack('C', 23)	=> '1111111111111111111111110011',
	pack('C', 24)	=> '1111111111111111111111110100',
	pack('C', 25)	=> '1111111111111111111111110101',
	pack('C', 26)	=> '1111111111111111111111110110',
	pack('C', 27)	=> '1111111111111111111111110111',
	pack('C', 28)	=> '1111111111111111111111111000',
	pack('C', 29)	=> '1111111111111111111111111001',
	pack('C', 30)	=> '1111111111111111111111111010',
	pack('C', 31)	=> '1111111111111111111111111011',
	pack('C', 32)	=> '010100',
	pack('C', 33)	=> '1111111000',
	pack('C', 34)	=> '1111111001',
	pack('C', 35)	=> '111111111010',
	pack('C', 36)	=> '1111111111001',
	pack('C', 37)	=> '010101',
	pack('C', 38)	=> '11111000',
	pack('C', 39)	=> '11111111010',
	pack('C', 40)	=> '1111111010',
	pack('C', 41)	=> '1111111011',
	pack('C', 42)	=> '11111001',
	pack('C', 43)	=> '11111111011',
	pack('C', 44)	=> '11111010',
	pack('C', 45)	=> '010110',
	pack('C', 46)	=> '010111',
	pack('C', 47)	=> '011000',
	pack('C', 48)	=> '00000',
	pack('C', 49)	=> '00001',
	pack('C', 50)	=> '00010',
	pack('C', 51)	=> '011001',
	pack('C', 52)	=> '011010',
	pack('C', 53)	=> '011011',
	pack('C', 54)	=> '011100',
	pack('C', 55)	=> '011101',
	pack('C', 56)	=> '011110',
	pack('C', 57)	=> '011111',
	pack('C', 58)	=> '1011100',
	pack('C', 59)	=> '11111011',
	pack('C', 60)	=> '111111111111100',
	pack('C', 61)	=> '100000',
	pack('C', 62)	=> '111111111011',
	pack('C', 63)	=> '1111111100',
	pack('C', 64)	=> '1111111111010',
	pack('C', 65)	=> '100001',
	pack('C', 66)	=> '1011101',
	pack('C', 67)	=> '1011110',
	pack('C', 68)	=> '1011111',
	pack('C', 69)	=> '1100000',
	pack('C', 70)	=> '1100001',
	pack('C', 71)	=> '1100010',
	pack('C', 72)	=> '1100011',
	pack('C', 73)	=> '1100100',
	pack('C', 74)	=> '1100101',
	pack('C', 75)	=> '1100110',
	pack('C', 76)	=> '1100111',
	pack('C', 77)	=> '1101000',
	pack('C', 78)	=> '1101001',
	pack('C', 79)	=> '1101010',
	pack('C', 80)	=> '1101011',
	pack('C', 81)	=> '1101100',
	pack('C', 82)	=> '1101101',
	pack('C', 83)	=> '1101110',
	pack('C', 84)	=> '1101111',
	pack('C', 85)	=> '1110000',
	pack('C', 86)	=> '1110001',
	pack('C', 87)	=> '1110010',
	pack('C', 88)	=> '11111100',
	pack('C', 89)	=> '1110011',
	pack('C', 90)	=> '11111101',
	pack('C', 91)	=> '1111111111011',
	pack('C', 92)	=> '1111111111111110000',
	pack('C', 93)	=> '1111111111100',
	pack('C', 94)	=> '11111111111100',
	pack('C', 95)	=> '100010',
	pack('C', 96)	=> '111111111111101',
	pack('C', 97)	=> '00011',
	pack('C', 98)	=> '100011',
	pack('C', 99)	=> '00100',
	pack('C', 100)	=> '100100',
	pack('C', 101)	=> '00101',
	pack('C', 102)	=> '100101',
	pack('C', 103)	=> '100110',
	pack('C', 104)	=> '100111',
	pack('C', 105)	=> '00110',
	pack('C', 106)	=> '1110100',
	pack('C', 107)	=> '1110101',
	pack('C', 108)	=> '101000',
	pack('C', 109)	=> '101001',
	pack('C', 110)	=> '101010',
	pack('C', 111)	=> '00111',
	pack('C', 112)	=> '101011',
	pack('C', 113)	=> '1110110',
	pack('C', 114)	=> '101100',
	pack('C', 115)	=> '01000',
	pack('C', 116)	=> '01001',
	pack('C', 117)	=> '101101',
	pack('C', 118)	=> '1110111',
	pack('C', 119)	=> '1111000',
	pack('C', 120)	=> '1111001',
	pack('C', 121)	=> '1111010',
	pack('C', 122)	=> '1111011',
	pack('C', 123)	=> '111111111111110',
	pack('C', 124)	=> '11111111100',
	pack('C', 125)	=> '11111111111101',
	pack('C', 126)	=> '1111111111101',
	pack('C', 127)	=> '1111111111111111111111111100',
	pack('C', 128)	=> '11111111111111100110',
	pack('C', 129)	=> '1111111111111111010010',
	pack('C', 130)	=> '11111111111111100111',
	pack('C', 131)	=> '11111111111111101000',
	pack('C', 132)	=> '1111111111111111010011',
	pack('C', 133)	=> '1111111111111111010100',
	pack('C', 134)	=> '1111111111111111010101',
	pack('C', 135)	=> '11111111111111111011001',
	pack('C', 136)	=> '1111111111111111010110',
	pack('C', 137)	=> '11111111111111111011010',
	pack('C', 138)	=> '11111111111111111011011',
	pack('C', 139)	=> '11111111111111111011100',
	pack('C', 140)	=> '11111111111111111011101',
	pack('C', 141)	=> '11111111111111111011110',
	pack('C', 142)	=> '111111111111111111101011',
	pack('C', 143)	=> '11111111111111111011111',
	pack('C', 144)	=> '111111111111111111101100',
	pack('C', 145)	=> '111111111111111111101101',
	pack('C', 146)	=> '1111111111111111010111',
	pack('C', 147)	=> '11111111111111111100000',
	pack('C', 148)	=> '111111111111111111101110',
	pack('C', 149)	=> '11111111111111111100001',
	pack('C', 150)	=> '11111111111111111100010',
	pack('C', 151)	=> '11111111111111111100011',
	pack('C', 152)	=> '11111111111111111100100',
	pack('C', 153)	=> '111111111111111011100',
	pack('C', 154)	=> '1111111111111111011000',
	pack('C', 155)	=> '11111111111111111100101',
	pack('C', 156)	=> '1111111111111111011001',
	pack('C', 157)	=> '11111111111111111100110',
	pack('C', 158)	=> '11111111111111111100111',
	pack('C', 159)	=> '111111111111111111101111',
	pack('C', 160)	=> '1111111111111111011010',
	pack('C', 161)	=> '111111111111111011101',
	pack('C', 162)	=> '11111111111111101001',
	pack('C', 163)	=> '1111111111111111011011',
	pack('C', 164)	=> '1111111111111111011100',
	pack('C', 165)	=> '11111111111111111101000',
	pack('C', 166)	=> '11111111111111111101001',
	pack('C', 167)	=> '111111111111111011110',
	pack('C', 168)	=> '11111111111111111101010',
	pack('C', 169)	=> '1111111111111111011101',
	pack('C', 170)	=> '1111111111111111011110',
	pack('C', 171)	=> '111111111111111111110000',
	pack('C', 172)	=> '111111111111111011111',
	pack('C', 173)	=> '1111111111111111011111',
	pack('C', 174)	=> '11111111111111111101011',
	pack('C', 175)	=> '11111111111111111101100',
	pack('C', 176)	=> '111111111111111100000',
	pack('C', 177)	=> '111111111111111100001',
	pack('C', 178)	=> '1111111111111111100000',
	pack('C', 179)	=> '111111111111111100010',
	pack('C', 180)	=> '11111111111111111101101',
	pack('C', 181)	=> '1111111111111111100001',
	pack('C', 182)	=> '11111111111111111101110',
	pack('C', 183)	=> '11111111111111111101111',
	pack('C', 184)	=> '11111111111111101010',
	pack('C', 185)	=> '1111111111111111100010',
	pack('C', 186)	=> '1111111111111111100011',
	pack('C', 187)	=> '1111111111111111100100',
	pack('C', 188)	=> '11111111111111111110000',
	pack('C', 189)	=> '1111111111111111100101',
	pack('C', 190)	=> '1111111111111111100110',
	pack('C', 191)	=> '11111111111111111110001',
	pack('C', 192)	=> '11111111111111111111100000',
	pack('C', 193)	=> '11111111111111111111100001',
	pack('C', 194)	=> '11111111111111101011',
	pack('C', 195)	=> '1111111111111110001',
	pack('C', 196)	=> '1111111111111111100111',
	pack('C', 197)	=> '11111111111111111110010',
	pack('C', 198)	=> '1111111111111111101000',
	pack('C', 199)	=> '1111111111111111111101100',
	pack('C', 200)	=> '11111111111111111111100010',
	pack('C', 201)	=> '11111111111111111111100011',
	pack('C', 202)	=> '11111111111111111111100100',
	pack('C', 203)	=> '111111111111111111111011110',
	pack('C', 204)	=> '111111111111111111111011111',
	pack('C', 205)	=> '11111111111111111111100101',
	pack('C', 206)	=> '111111111111111111110001',
	pack('C', 207)	=> '1111111111111111111101101',
	pack('C', 208)	=> '1111111111111110010',
	pack('C', 209)	=> '111111111111111100011',
	pack('C', 210)	=> '11111111111111111111100110',
	pack('C', 211)	=> '111111111111111111111100000',
	pack('C', 212)	=> '111111111111111111111100001',
	pack('C', 213)	=> '11111111111111111111100111',
	pack('C', 214)	=> '111111111111111111111100010',
	pack('C', 215)	=> '111111111111111111110010',
	pack('C', 216)	=> '111111111111111100100',
	pack('C', 217)	=> '111111111111111100101',
	pack('C', 218)	=> '11111111111111111111101000',
	pack('C', 219)	=> '11111111111111111111101001',
	pack('C', 220)	=> '1111111111111111111111111101',
	pack('C', 221)	=> '111111111111111111111100011',
	pack('C', 222)	=> '111111111111111111111100100',
	pack('C', 223)	=> '111111111111111111111100101',
	pack('C', 224)	=> '11111111111111101100',
	pack('C', 225)	=> '111111111111111111110011',
	pack('C', 226)	=> '11111111111111101101',
	pack('C', 227)	=> '111111111111111100110',
	pack('C', 228)	=> '1111111111111111101001',
	pack('C', 229)	=> '111111111111111100111',
	pack('C', 230)	=> '111111111111111101000',
	pack('C', 231)	=> '11111111111111111110011',
	pack('C', 232)	=> '1111111111111111101010',
	pack('C', 233)	=> '1111111111111111101011',
	pack('C', 234)	=> '1111111111111111111101110',
	pack('C', 235)	=> '1111111111111111111101111',
	pack('C', 236)	=> '111111111111111111110100',
	pack('C', 237)	=> '111111111111111111110101',
	pack('C', 238)	=> '11111111111111111111101010',
	pack('C', 239)	=> '11111111111111111110100',
	pack('C', 240)	=> '11111111111111111111101011',
	pack('C', 241)	=> '111111111111111111111100110',
	pack('C', 242)	=> '11111111111111111111101100',
	pack('C', 243)	=> '11111111111111111111101101',
	pack('C', 244)	=> '111111111111111111111100111',
	pack('C', 245)	=> '111111111111111111111101000',
	pack('C', 246)	=> '111111111111111111111101001',
	pack('C', 247)	=> '111111111111111111111101010',
	pack('C', 248)	=> '111111111111111111111101011',
	pack('C', 249)	=> '1111111111111111111111111110',
	pack('C', 250)	=> '111111111111111111111101100',
	pack('C', 251)	=> '111111111111111111111101101',
	pack('C', 252)	=> '111111111111111111111101110',
	pack('C', 253)	=> '111111111111111111111101111',
	pack('C', 254)	=> '111111111111111111111110000',
	pack('C', 255)	=> '11111111111111111111101110',
	'_eos'		=> '111111111111111111111111111111',
}};

sub huff {
	my ($string) = @_;
	my $code = &huff_code;

	my $ret = join '', map { $code->{$_} } (split //, $string);
	my $len = length($ret) + (8 - length($ret) % 8);
	$ret .= $code->{_eos};

	return pack("B$len", $ret);
}

sub dehuff {
	my ($string) = @_;
	my $code = &huff_code;
	my %decode = reverse %$code;

	my $ret = ''; my $c = '';
	for (split //, unpack('B*', $string)) {
		$c .= $_;
		next unless exists $decode{$c};
		last if $decode{$c} eq '_eos';

		$ret .= $decode{$c};
		$c = '';
	}

	return $ret;
}

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

# for tests with multiple header fields

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => 8083,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		next if $headers eq '';
		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/cookie') {

			my ($cookie, $cookie2) = $headers =~ /Cookie: (.+)/ig;
			$cookie2 = '' unless defined $cookie2;

			my ($cookie_a, $cookie_c) = ('', '');
			$cookie_a = $1 if $headers =~ /X-Cookie-a: (.+)/i;
			$cookie_c = $1 if $headers =~ /X-Cookie-c: (.+)/i;

			print $client <<EOF;
HTTP/1.1 200 OK
Connection: close
X-Sent-Cookie: $cookie
X-Sent-Cookie2: $cookie2
X-Sent-Cookie-a: $cookie_a
X-Sent-Cookie-c: $cookie_c

EOF

		} elsif ($uri eq '/set-cookie') {

			print $client <<EOF;
HTTP/1.1 200 OK
Connection: close
Set-Cookie: a=b
Set-Cookie: c=d

EOF

		}

	} continue {
		close $client;
	}
}

###############################################################################
