#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream geo module.

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

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_map stream_geo/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    geo $geo {
        127.0.0.0/8  loopback;
        192.0.2.0/24 test;
        0.0.0.0/0    world;
    }

    geo $remote_addr $geo_from_addr {
        127.0.0.0/8  loopback;
        192.0.2.0/24 test;
    }

    map $server_port $var {
        %%PORT_8080%%  "192.0.2.1";
        %%PORT_8081%%  "10.0.0.1";
    }

    geo $var $geo_from_var {
        default      default;
        127.0.0.0/8  loopback;
        192.0.2.0/24 test;
    }

    geo $var $geo_world {
        127.0.0.0/8  loopback;
        192.0.2.0/24 test;
        0.0.0.0/0    world;
    }

    geo $geo_ranges {
        ranges;
        default      default;
        127.0.0.0-127.255.255.255  loopback;
        192.0.2.0-192.0.2.255      test;
    }

    server {
        listen  127.0.0.1:8080;
        return  "geo:$geo
                 geo_from_addr:$geo_from_addr
                 geo_from_var:$geo_from_var
                 geo_ranges:$geo_ranges";
    }

    server {
        listen  127.0.0.1:8081;
        return  $geo_from_var;
    }

    server {
        listen  127.0.0.1:8082;
        return  $geo_world;
    }
}

EOF

$t->try_run('no stream geo');
$t->plan(6);

###############################################################################

my %data = stream()->read() =~ /(\w+):(\w+)/g;
is($data{geo}, 'loopback', 'geo');
is($data{geo_from_addr}, 'loopback', 'geo from addr');
is($data{geo_from_var}, 'test', 'geo from var');
is($data{geo_ranges}, 'loopback', 'geo ranges');

is(stream('127.0.0.1:' . port(8081))->read(), 'default', 'geo default');
is(stream('127.0.0.1:' . port(8082))->read(), 'world', 'geo world');

###############################################################################
