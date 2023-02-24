#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream SRV records.

###############################################################################

use warnings;
use strict;
#use Data::Dumper;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

# the test depends on availability of 127.0.0.0/8 subnet on targets
plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()->has(qw/http http_api proxy upstream_zone/)
	->has_daemon("dnsmasq")->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
# to (possibly) improve coverage a bit
worker_processes 4;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        zone z 1m;
        server backends.example.com service=http resolve;

        resolver 127.0.0.1:5454 valid=1s ipv6=off;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_pass http://u;
        }

        location /api/ {
            api /;
        }
    }

    # backends
    server {
        error_log backend1.log debug;
        listen 127.0.0.1:%%PORT_8081%%;
        location / { return 200 "B1"; }
    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.2:%%PORT_8082%%;
        location / { return 200 "B2"; }
    }
}

EOF

my $tdir = $t->testdir();

# TODO: use substituted ports for parallel execution for DNS server
$t->write_file_expand('dns.conf', <<'EOF');
# listen on this port
port=5454
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this fil
addn-hosts=%%TESTDIR%%/test_hosts

# SRV records
srv-host=_http._tcp.backends.example.com,b1.example.com,%%PORT_8081%%
srv-host=_http._tcp.backends.example.com,b2.example.com,%%PORT_8082%%
EOF

# ipv6 entries are stubs for resolver
$t->write_file_expand('test_hosts', <<'EOF');
127.0.0.1  b1.example.com
127.0.0.2  b2.example.com
::1 b1.example.com
::1 b2.example.com
EOF


my $dconf = $t->testdir()."/dns.conf";

$t->run_daemon('dnsmasq', '-C', $tdir."/dns.conf", '-k', "--log-facility=$tdir/dns.log", '-q');
$t->wait_for_resolver('127.0.0.1', 5464, 'b1.example.com', '127.0.0.1');

$t->run();

###############################################################################

my @ports = my ($port1, $port2) = (port(8081), port(8082));

my ($j, $v);

# wait for nginx resolver to complete query
for (1 .. 50) {
    last if http_get('/') =~ qr /200 OK/;
    select undef, undef, undef, 0.1;
}

# expect that upstream contains addresses from 'test_hosts' file

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1");
is($j->{'server'}, 'backends.example.com', 'b1 address resolved from srv');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.2:$port2");
is($j->{'server'}, 'backends.example.com', 'b2 address resolved from srv');


###############################################################################

sub get_json {
    my ($uri) = @_;
    my $response = http_get($uri);
    my ($headers,$body) =  split /\n\r/, $response, 2;
    #print($body);
    my $json;
    eval { $json = JSON::PP::decode_json($body) };
    if ($@) {
        return undef;
    }

    return $json;
}

