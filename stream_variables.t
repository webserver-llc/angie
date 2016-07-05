#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream variables.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream dgram /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return ipv6/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    server {
        listen  127.0.0.1:%%PORT_0%%;
        return  $connection:$nginx_version:$hostname:$pid:$bytes_sent;
    }

    server {
        listen  127.0.0.1:%%PORT_1%%;
        listen  [::1]:%%PORT_1%%;
        return  $remote_addr:$remote_port:$server_addr:$server_port;
    }

    server {
        listen  127.0.0.1:%%PORT_2%%;
        proxy_pass  [::1]:%%PORT_1%%;
    }

    server {
        listen  127.0.0.1:%%PORT_3%%;
        listen  [::1]:%%PORT_3%%;
        return  $binary_remote_addr;
    }

    server {
        listen  127.0.0.1:%%PORT_4%%;
        proxy_pass  [::1]:%%PORT_3%%;
    }

    server {
        listen  127.0.0.1:%%PORT_5%%;
        return  $msec!$time_local!$time_iso8601;
    }
}

EOF

$t->try_run('no stream return')->plan(6);

###############################################################################

chomp(my $hostname = lc `hostname`);
like(stream()->read(), qr/^\d+:[\d.]+:$hostname:\d+:0$/, 'vars');

my $dport = port(1);
my $s = stream("127.0.0.1:$dport");
my $lport = $s->sockport();
is($s->read(), "127.0.0.1:$lport:127.0.0.1:$dport", 'addr');

my $data = stream('127.0.0.1:' . port(2))->read();
like($data, qr/^::1:\d+:::1:\d+$/, 'addr ipv6');

$data = stream('127.0.0.1:' . port(3))->read();
is(unpack("H*", $data), '7f000001', 'binary addr');

$data = stream('127.0.0.1:' . port(4))->read();
is(unpack("H*", $data), '0' x 31 . '1', 'binary addr ipv6');

$data = stream('127.0.0.1:' . port(5))->read();
like($data, qr#^\d+.\d+![-+\w/: ]+![-+\dT:]+$#, 'time');

###############################################################################
