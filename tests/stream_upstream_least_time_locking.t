#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Regression test for a locking bug in stream least_time balancer:
# when all peers are down, the peers rwlock was not released,
# causing 100% CPU on subsequent connections.

##############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;

##############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/stream stream_upstream_least_time stream_upstream_zone/)
	->plan(2);

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    upstream u {
        zone u 128k;
        server 127.0.0.1:8081 down;
        server 127.0.0.1:8082 down;
        least_time connect;
    }

    server {
        listen 127.0.0.1:8080;
        proxy_pass u;
    }
}

EOF

$t->run();

# First connection: all peers down, connection is rejected.
# Without the fix, the write lock is leaked.
my $r = stream('127.0.0.1:' . port(8080))->read();
is($r, '', 'all peers down - connection closed');

# Second connection: without the fix, this would spin on the
# leaked rwlock, causing 100% CPU and a test timeout.
$r = stream('127.0.0.1:' . port(8080))->read();
is($r, '', 'second connection also closed');

