#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream SRV records.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/http_start http_get http_end port/;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# the test depends on availability of 127.0.0.0/8 subnet on targets
plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()->has(qw/http http_api proxy upstream_zone/)
	->has_daemon("dnsmasq")->plan(4)
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

        location /u {
            proxy_pass http://u/;
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
        location /slow {
            limit_rate 40;
            return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        }

    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.2:%%PORT_8082%%;
        location / { return 200 "B2"; }
        location /slow {
            limit_rate 40;
            return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        }
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
# take records from this file
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

$t->write_file_expand('dns2.conf', <<'EOF');
# listen on this port
port=5454
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this file
addn-hosts=%%TESTDIR%%/test_hosts2

# return NXDOMAIN for this
address=/b2.example.com/

# SRV records
srv-host=_http._tcp.backends.example.com,b1.example.com,%%PORT_8081%%
srv-host=_http._tcp.backends.example.com,b2.example.com,%%PORT_8082%%
EOF

$t->write_file_expand('test_hosts2', <<'EOF');
127.0.0.1  b1.example.com
::1 b1.example.com
EOF

$t->write_file_expand('dns3.conf', <<'EOF');
# listen on this port
port=5454
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this file
addn-hosts=%%TESTDIR%%/test_hosts2

# return NXDOMAIN for this
address=/backends.example.com/

EOF

my $dconf = $t->testdir()."/dns.conf";

$t->run_daemon('dnsmasq', '-C', "$tdir/dns.conf", '-k',
	"--log-facility=$tdir/dns.log", '-q');
$t->wait_for_resolver('127.0.0.1', 5454, 'b1.example.com', '127.0.0.1');

$t->run();

###############################################################################

my ($port1, $port2) = (port(8081), port(8082));

# wait for nginx resolver to complete query
for (1 .. 50) {
	last if http_get('/') =~ qr /200 OK/;
	select undef, undef, undef, 0.1;
}

# expect that upstream contains addresses from 'test_hosts' file

my $j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1");
is($j->{server}, 'backends.example.com', 'b1 address resolved from srv');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.2:$port2");
is($j->{'server'}, 'backends.example.com', 'b2 address resolved from srv');

my $s = http_start_uri('/u/slow'); # connects to b1
my $s2 = http_start_uri('/u/slow'); # connects to b2

$t->stop_daemons();

# start DNS server with new config, b2 disappears from backends.example.com
$t->run_daemon('dnsmasq', '-C', "$tdir/dns2.conf", '-k',
	"--log-facility=$tdir/dns.log", '-q');
$t->wait_for_resolver('127.0.0.1', 5454, 'b1.example.com', '127.0.0.1');

# let various resolve timers run
select undef, undef, undef, 2;

$j = get_json("/api/status/http/upstreams/u/127.0.0.2:$port2");
is($j->{'error'}, 'PathNotFound', 'b2.example.com disappeared');

my $res = http_end($s);
my $res2 = http_end($s2);


# whole backends.example.com disappears
$t->stop_daemons();

# start DNS server with new config,
$t->run_daemon('dnsmasq', '-C', "$tdir/dns3.conf", '-k',
	"--log-facility=$tdir/dns.log", '-q');
$t->wait_for_resolver('127.0.0.1', 5454, 'b1.example.com', '127.0.0.1');

# let various resolve timers run
select undef, undef, undef, 2;

$j = get_json("/api/status/http/upstreams/u/peers");
is(%$j, 0, "example.com disappeared");


###############################################################################

sub http_start_uri {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => '127.0.0.1',
		PeerPort => port(8080)
	)
		or die "cannot create socket: $!\n";

	http_start(<<EOF, socket => $s);
GET $uri HTTP/1.0
Host: localhost

EOF

	return $s;
}

