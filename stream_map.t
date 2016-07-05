#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream map module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_map/)
	->has(qw/http rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    map $server_port $x {
        %%PORT_0%%             literal;
        default                default;
        ~(%%PORT_2%%)          $1;
        ~(?P<ncap>%%PORT_3%%)  $ncap;
    }

    server {
        listen  127.0.0.1:%%PORT_0%%;
        listen  127.0.0.1:%%PORT_1%%;
        listen  127.0.0.1:%%PORT_2%%;
        listen  127.0.0.1:%%PORT_3%%;
        return  $x;
    }

    server {
        listen  127.0.0.1:%%PORT_4%%;
        return  $x:${x};
    }
}

EOF

$t->try_run('no stream map')->plan(5);

###############################################################################

is(stream('127.0.0.1:' . port(0))->read(), 'literal', 'literal');
is(stream('127.0.0.1:' . port(1))->read(), 'default', 'default');
is(stream('127.0.0.1:' . port(2))->read(), port(2), 'capture');
is(stream('127.0.0.1:' . port(3))->read(), port(3), 'named capture');
is(stream('127.0.0.1:' . port(4))->read(), 'default:default', 'braces');

###############################################################################
