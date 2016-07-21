#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream proxy module with complex value.

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

my $t = Test::Nginx->new()->has(qw/stream stream_return/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    upstream 8081 {
        server 127.0.0.1:8091;
    }

    upstream 8082 {
        server 127.0.0.1:8092;
        server 127.0.0.1:8093;
    }

    server {
        listen      127.0.0.1:8081;
        listen      127.0.0.1:8082;
        proxy_pass  $server_port;
    }

    server {
        listen      127.0.0.1:8083;
        proxy_pass  $server_addr:%%PORT_8093%%;
    }

    server {
        listen      127.0.0.1:8091;
        listen      127.0.0.1:8092;
        listen      127.0.0.1:8093;
        return      $server_port;
    }
}

EOF

$t->try_run('no stream proxy_pass with complex value')->plan(5);

###############################################################################

is(stream('127.0.0.1:' . port(8081))->io('foo'), port(8091), 'upstream');
is(stream('127.0.0.1:' . port(8081))->io('foo'), port(8091), 'upstream again');

is(stream('127.0.0.1:' . port(8082))->io('foo'), port(8092), 'upstream 2');
is(stream('127.0.0.1:' . port(8082))->io('foo'), port(8093), 'upstream second');

is(stream('127.0.0.1:' . port(8083))->io('foo'), port(8093), 'implicit');

###############################################################################
