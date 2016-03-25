#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with request body.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(34);

$t->todo_alerts();

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

        location / { }
        location /proxy2/ {
            add_header X-Body $request_body;
            add_header X-Body-File $request_body_file;
            client_body_in_file_only on;
            proxy_pass http://127.0.0.1:8081/;
        }
        location /client_max_body_size {
            add_header X-Body $request_body;
            add_header X-Body-File $request_body_file;
            client_body_in_single_buffer on;
            client_body_in_file_only on;
            proxy_pass http://127.0.0.1:8081/;
            client_max_body_size 10;
        }
    }
}

EOF

$t->write_file('index.html', '');
$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

# request body (uses proxied response)

my $sess = new_session();
my $sid = new_stream($sess, { path => '/proxy2/t.html', body_more => 1 });
h2_body($sess, 'TEST');
my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TEST', 'request body');

# request body with padding (uses proxied response)

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t.html', body_more => 1 });
h2_body($sess, 'TEST', { body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TEST',
	'request body with padding');

$sid = new_stream($sess);
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'request body with padding - next');

# request body sent in multiple DATA frames in a single packet

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t.html', body_more => 1 });
h2_body($sess, 'TEST', { body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TEST',
	'request body in multiple frames');

# request body sent in multiple DATA frames, each in its own packet

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/t.html', body_more => 1 });
h2_body($sess, 'TEST', { body_more => 1 });
select undef, undef, undef, 0.1;
h2_body($sess, 'MOREDATA');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTMOREDATA',
	'request body in multiple frames separately');

# request body with an empty DATA frame
# "zero size buf in output" alerts seen

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy2/', body_more => 1 });
h2_body($sess, '');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'request body - empty');

TODO: {
local $TODO = 'not yet';

ok($frame->{headers}{'x-body-file'}, 'request body - empty body file');

}

TODO: {
todo_skip 'empty body file', 1 unless $frame->{headers}{'x-body-file'};

is(read_body_file($frame->{headers}{'x-body-file'}), '',
	'request body - empty content');

}

# malformed request body length not equal to content-length

$sess = new_session();
$sid = new_stream($sess,
	{ body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/client_max_body_size', mode => 1 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'content-length', value => '5', mode => 1 }]});
h2_body($sess, 'TEST');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 400, 'request body less than content-length');

$sid = new_stream($sess,
	{ body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 0 },
	{ name => ':scheme', value => 'http', mode => 0 },
	{ name => ':path', value => '/client_max_body_size', mode => 1 },
	{ name => ':authority', value => 'localhost', mode => 1 },
	{ name => 'content-length', value => '3', mode => 1 }]});
h2_body($sess, 'TEST');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 400, 'request body more than content-length');

# client_max_body_size

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST12');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'client_max_body_size - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'client_max_body_size - body');

# client_max_body_size - limited

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST123');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413, 'client_max_body_size - limited');

# client_max_body_size - many DATA frames

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST12', { body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'client_max_body_size many - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'client_max_body_size many - body');

# client_max_body_size - many DATA frames - limited

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST123', { body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413, 'client_max_body_size many - limited');

# client_max_body_size - padded DATA

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST12', { body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'client_max_body_size pad - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'client_max_body_size pad - body');

# client_max_body_size - padded DATA - limited

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST123', { body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413, 'client_max_body_size pad - limited');

# client_max_body_size - many padded DATA frames

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST12', { body_padding => 42, body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'client_max_body_size many pad - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'client_max_body_size many pad - body');

# client_max_body_size - many padded DATA frames - limited

$sess = new_session();
$sid = new_stream($sess, { path => '/client_max_body_size/t.html',
	body_more => 1 });
h2_body($sess, 'TESTTEST123', { body_padding => 42, body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413,
	'client_max_body_size many pad - limited');

# request body without content-length

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST12');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'request body without content-length - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'request body without content-length - body');

# request body without content-length - limited

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST123');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413,
	'request body without content-length - limited');

# request body without content-length - many DATA frames

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST12', { body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'request body without content-length many - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'request body without content-length many - body');

# request body without content-length - many DATA frames - limited

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST123', { body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413,
	'request body without content-length many - limited');

# request body without content-length - padding

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST12', { body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'request body without content-length pad - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST12',
	'request body without content-length pad - body');

# request body without content-length - padding - limited

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST123', { body_padding => 42 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413,
	'request body without content-length pad - limited');

# request body without content-length - padding with many DATA frames

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST', { body_padding => 42, body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200,
	'request body without content-length many pad - status');
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TESTTEST',
	'request body without content-length many pad - body');

# request body without content-length - padding with many DATA frames - limited

$sess = new_session();
$sid = new_stream($sess, { body_more => 1, headers => [
	{ name => ':method', value => 'GET', mode => 2 },
	{ name => ':scheme', value => 'http', mode => 2 },
	{ name => ':path', value => '/client_max_body_size', mode => 2 },
	{ name => ':authority', value => 'localhost', mode => 2 }]});
h2_body($sess, 'TESTTEST123', { body_padding => 42, body_split => [2] });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 413,
	'request body without content-length many pad - limited');

###############################################################################

sub read_body_file {
	my ($path) = @_;
	open FILE, $path or return "$!";
	local $/;
	my $content = <FILE>;
	close FILE;
	return $content;
}

###############################################################################
