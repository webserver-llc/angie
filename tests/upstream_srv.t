#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream SRV records.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_bag/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/http_start http_get http_end port/;
use Test::Utils qw/get_json wait_for/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# the test depends on availability of 127.0.0.0/8 subnet on targets
plan(skip_all => '127.0.0.2 local address required')
	unless defined IO::Socket::INET->new( LocalAddr => '127.0.0.2' );

my $t = Test::Nginx->new()->has(qw/http http_api proxy upstream_zone rewrite/)
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
            add_header X-Backend B1;
            limit_rate 40;
            return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        }
    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.2:%%PORT_8082%%;
        location / { return 200 "B2"; }
        location /slow {
            add_header X-Backend B2;
            limit_rate 40;
            return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        }
    }
}

EOF

my ($port1, $port2) = (port(8081), port(8082));

# TODO: use substituted ports for parallel execution for DNS server
my %addrs = (
	'b1.example.com' => ['127.0.0.1', '::1'],
	'b2.example.com' => ['127.0.0.2', '::1']
);

my @srv_records = (
	"_http._tcp.backends.example.com,b1.example.com,$port1",
	"_http._tcp.backends.example.com,b2.example.com,$port2"
);

$t->start_resolver(5454, \%addrs, {srvs => \@srv_records});

$t->run()->plan(10);

# wait for all backends to be available
$t->waitforsocket('127.0.0.1:' . $port1);
$t->waitforsocket('127.0.0.2:' . $port2);

###############################################################################

# wait for nginx resolver to complete query
wait_for(
	sub {http_get('/') =~ qr /200 OK/}, 'nginx resolver completed query', 5);

# expect that upstream contains addresses from 'test_hosts' file

my $j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1");
is($j->{server}, 'backends.example.com', 'b1 address resolved from srv');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.2:$port2");
is($j->{server}, 'backends.example.com', 'b2 address resolved from srv');

# connects to b1/b2
my $s = http_start_uri('/u/slow');
my $s2 = http_start_uri('/u/slow');

# start DNS server with new config, b2 disappears from backends.example.com
%addrs = (
	'b1.example.com' => ['127.0.0.1', '::1']
);

$t->restart_resolver(5454, \%addrs, {srvs => \@srv_records,
	nxaddrs => ['b2.example.com']});

# let various resolve timers run
wait_for(
	sub {
		my $j = get_json("/api/status/http/upstreams/u/127.0.0.2:$port2");
		return !defined $j->{server} && $j->{error} eq 'PathNotFound';
	},
	'b2.example.com disappeared', 5
);

# verify that active connections aren't killed when a peer is removed from SRV

my $res = http_end($s);
my ($backend1) = $res =~ /^X-Backend: (B\d)\s?$/m;
ok(defined $backend1, 'first slow request has X-Backend header');
like($res, qr/200 OK/, 'first slow request has code 200');

my $res2 = http_end($s2);
my ($backend2) = $res2 =~ /^X-Backend: (B\d)\s?$/m;
ok(defined $backend2, 'second slow request has X-Backend header');
like($res2, qr/200 OK/, 'second slow request has code 200');

cmp_bag([$backend1, $backend2], [qw(B1 B2)], 'both backends answered');

# start DNS server with new config,
# whole backends.example.com disappears
$t->restart_resolver(5454, \%addrs, {nxaddrs => ['backends.example.com']});

# let various resolve timers run
wait_for(
	sub {
		my $j = get_json('/api/status/http/upstreams/u/peers');
		return unless defined $j;
		return !scalar keys %$j;
	},
	'example.com disappeared', 5
);

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

