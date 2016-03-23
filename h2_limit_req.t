#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with limit_req.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite limit_req/)
	->plan(6);

# Some systems may have also a bug in not treating zero writev iovcnt as EINVAL

$t->todo_alerts();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_req_zone   $binary_remote_addr  zone=req:1m rate=1r/s;

    server {
        listen       127.0.0.1:8080 http2;
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
        location /limit_req {
            limit_req  zone=req burst=2;
            alias %%TESTDIR%%/t.html;
        }
        location /proxy_limit_req/ {
            add_header X-Body $request_body;
            add_header X-Body-File $request_body_file;
            client_body_in_file_only on;
            proxy_pass http://127.0.0.1:8081/;
            limit_req  zone=req burst=2;
        }
    }
}

EOF

$t->write_file('index.html', '');
$t->write_file('t.html', 'SEE-THIS');
$t->run();

###############################################################################

# request body delayed in limit_req

my $sess = new_session();
my $sid = new_stream($sess, { path => '/proxy_limit_req/', body_more => 1 });
h2_body($sess, 'TEST');
my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TEST',
	'request body - limit req');

# request body delayed in limit_req - with an empty DATA frame

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy_limit_req/', body_more => 1 });
h2_body($sess, '');
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'request body - limit req - empty');

# predict send windows

$sid = new_stream($sess);
my ($maxwin) = sort {$a <=> $b} $sess->{streams}{$sid}, $sess->{conn_window};

SKIP: {
skip 'leaves coredump', 1 unless $t->has_version('1.9.7');
skip 'not enough window', 1 if $maxwin < 5;

$sess = new_session();
$sid = new_stream($sess, { path => '/proxy_limit_req/', body => 'TEST2' });
select undef, undef, undef, 1.1;
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is(read_body_file($frame->{headers}->{'x-body-file'}), 'TEST2',
	'request body - limit req 2');

}

# partial request body data frame received (to be discarded) within request
# delayed in limit_req, the rest of data frame is received after response

$sess = new_session();

SKIP: {
skip 'not enough window', 1 if $maxwin < 4;

TODO: {
todo_skip 'use-after-free', 1 unless $ENV{TEST_NGINX_UNSAFE}
	or $t->has_version('1.9.12');

$sid = new_stream($sess, { path => '/limit_req', body => 'TEST', split => [61],
	split_delay => 1.1 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'discard body - limit req - limited');

}

}

$sid = new_stream($sess, { path => '/' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'discard body - limit req - next');

# ditto, but instead of receiving the rest of data frame, connection is closed
# 'http request already closed while closing request' alert can be produced

SKIP: {
skip 'not enough window', 1 if $maxwin < 4;

TODO: {
todo_skip 'use-after-free', 1 unless $ENV{TEST_NGINX_UNSAFE}
	or $t->has_version('1.9.12');

$sess = new_session();
$sid = new_stream($sess, { path => '/limit_req', body => 'TEST', split => [61],
	abort => 1 });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, '200', 'discard body - limit req - eof');

select undef, undef, undef, 1.1;
undef $sess;

}

}

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
