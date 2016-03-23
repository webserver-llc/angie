#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with variables.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 rewrite/)->plan(4)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2;
        server_name  localhost;

        location /h2 {
            return 200 $http2;
        }
        location /sp {
            return 200 $server_protocol;
        }
        location /scheme {
            return 200 $scheme;
        }
        location /https {
            return 200 $https;
        }
    }
}

EOF

$t->run();

###############################################################################

# $http2

my $sess = new_session();
my $sid = new_stream($sess, { path => '/h2' });
my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

my ($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'h2c', 'http variable - h2c');

# $server_protocol

$sess = new_session();
$sid = new_stream($sess, { path => '/sp' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'HTTP/2.0', 'server_protocol variable');

# $scheme

$sess = new_session();
$sid = new_stream($sess, { path => '/scheme' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, 'http', 'scheme variable');

# $https

$sess = new_session();
$sid = new_stream($sess, { path => '/https' });
$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "DATA" } @$frames;
is($frame->{data}, '', 'https variable');

###############################################################################
