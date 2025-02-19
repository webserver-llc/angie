#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream re-resolve.

###############################################################################

use warnings;
use strict;

use Test::Most;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/http_start port http_get http_end/;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# the test depends on availability of 127.0.0.0/8 subnet on targets
plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()
	->has(qw/http http_api proxy upstream_zone --with-debug/);

# see https://trac.nginx.org/nginx/ticket/1831
plan(skip_all => "perl >= 5.32 required")
	if ($t->has_module('perl') && $] < 5.032000);

$t->write_file_expand('nginx.conf', <<'EOF');

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
        server foo.example.com:%%PORT_8081%% resolve;
        server bar.example.com:%%PORT_8082%% resolve;
        server backup.example.com:%%PORT_8081%% resolve backup;
        server nonexist.example.com:%%PORT_8081%% resolve backup;

        resolver 127.0.0.1:5353 valid=1s ipv6=off;
    }

    upstream u2 {
        zone z 1m;
        server baz.example.com:%%PORT_8081%% resolve;

        resolver 127.0.0.1:5353 valid=1s ipv6=off;
        resolver_timeout 1s;
    }


    # verify tries - multiple servers
    upstream u3 {
        zone z 1m;

        server multi.example.com:%%PORT_8081%% resolve;

        resolver 127.0.0.1:5353 valid=1s ipv6=off;
        resolver_timeout 1s;
    }

    # verify tries - regular servers
    upstream u4 {
        zone z 1m;

        server bar.example.com:%%PORT_8081%% resolve;
        server qux.example.com:%%PORT_8081%% resolve;

        resolver 127.0.0.1:5353 valid=1s ipv6=off;
        resolver_timeout 1s;
    }

    server {
        listen       127.0.0.2:%%PORT_8081%%;

        location / {
            return 404;
        }
    }

    server {
        listen       127.0.0.6:%%PORT_8081%%;

        location / {
            return 200 "goodreply";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_pass http://u;
        }

        location /u2 {
            proxy_pass http://u2/;
        }

        location /u3 {
            add_header  "X-Upstream-Status" "US=$upstream_status";
            proxy_next_upstream http_404;
            proxy_pass http://u3/;
        }

        location /u4 {
            add_header  "X-Upstream-Status" "US=$upstream_status";
            proxy_next_upstream http_404;
            proxy_pass http://u4/;
        }

        location /api/ {
            api /;
        }
    }

    # backends
    server {
        error_log backend1.log debug;
        listen 127.0.0.1:%%PORT_8081%%;
        listen 127.0.0.5:%%PORT_8081%%;
        location / { return 200 "B1"; }
        location /slow {
            limit_rate 40;
            return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        }
    }
    server {
        error_log backend2.log debug;
        listen 127.0.0.1:%%PORT_8082%%;
        location / { return 200 "B2"; }
    }
}

EOF

# TODO: use substituted ports for parallel execution for DNS server
my %addrs = (
    'foo.example.com'    => ['127.0.0.1', '::1'],
    'bar.example.com'    => ['127.0.0.2', '::1'],
    'backup.example.com' => ['127.0.0.3', '127.0.0.4', '::1'],
    'baz.example.com'    => ['127.0.0.5', '::1'],
    'qux.example.com'    => ['127.0.0.6'],
    'multi.example.com'  => ['127.0.0.2', '127.0.0.6']
);

$t->start_resolver(5353, \%addrs);

$t->run()->plan(16);

###############################################################################

my ($port1, $port2) = (port(8081), port(8082));

# wait for nginx resolver to complete query
for (1 .. 50) {
	last if http_get('/') =~ qr /200 OK/;
	select undef, undef, undef, 0.1;
}

# expect that upstream contains addresses from 'test_hosts' file

my $j = get_json("/api/status/http/upstreams/u/peers/127.0.0.1:$port1");
is($j->{server}, 'foo.example.com:' . $port1, 'foo.example.com is resolved');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.2:$port2");
is($j->{server}, 'bar.example.com:' . $port2, 'bar.example.com resolved');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.3:$port1");
is($j->{server}, 'backup.example.com:' . $port1,
	'backup.example.com addr 1 resolved');

$j = get_json("/api/status/http/upstreams/u/peers/127.0.0.4:$port1");
is($j->{server}, 'backup.example.com:' . $port1,
	'backup.example.com addr 2 resolved');

# verify tries - multiple
# u3: multi.example.com:8081
#       127.0.0.2	404
#       127.0.0.6	200
my $upstream_status_re = qr/X-Upstream-Status: US=([^\n\r]+)/;
my ($upstream_status_1) = http_get("/u3") =~ $upstream_status_re;
my ($upstream_status_2) = http_get("/u3") =~ $upstream_status_re;

# the order is not significant
cmp_bag(
	[$upstream_status_1, $upstream_status_2], ['404, 200', '200'],
	'multiple - request 1 and 2'
);

# verify tries - regular
# u4: bar.example.com:8081
#       127.0.0.2	404
#     qux.example.com:8081
#       127.0.0.6	200
($upstream_status_1) = http_get("/u4") =~ $upstream_status_re;
($upstream_status_2) = http_get("/u4") =~ $upstream_status_re;

# the order is not significant
cmp_bag(
	[$upstream_status_1, $upstream_status_2], ['404, 200', '200'],
	'regular - request 1 and 2'
);

# perform reload to trigger the codepath for pre-resolve
$t->reload('/api/status/angie/generation');

# no need to wait for resolver, we expect cached result

$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.1:$port1"}{server}, "foo.example.com:$port1",
	'foo.example.com is found after reload');
is($j->{"127.0.0.2:$port2"}{server}, "bar.example.com:$port2",
	'bar.example.com is found after reload');


# now stop DNS daemon to prevent resolving, reload nginx
# and verify upstreams are still accessible

$t->stop_resolver();
$t->reload('/api/status/angie/generation');

$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.1:$port1"}{server}, "foo.example.com:$port1",
	'foo.example.com is saved');
is($j->{"127.0.0.2:$port2"}{server}, "bar.example.com:$port2",
	'bar.example.com is saved');


# start DNS server with new config, addresses changed
%addrs = (
    'foo.example.com' => ['127.0.0.3', '::1'],
    'bar.example.com' => ['127.0.0.4', '::1'],
    'baz.example.com' => ['127.0.0.5', '::1']
);
my @nxaddrs = ('backup.example.com');

$t->start_resolver(5353, \%addrs, {nxaddrs => \@nxaddrs});

# reload nginx to force resolve
$t->reload('/api/status/angie/generation');

# wait 3 seconds to ensure re-resolve (valid=1s)
select undef, undef, undef, 3;

# expect 127.0.0.3 is now foo instead of 'backup'
$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.3:$port1"}{server}, "foo.example.com:$port1",
	'foo.example.com is new');
is($j->{"127.0.0.4:$port2"}{server}, "bar.example.com:$port2",
	'bar.example.com is new');


# Trigger zombies paths and test for debug refcount

# 1) start 2 long requests  (backend is baz.example.com)

$j = get_json("/api/status/http/upstreams/u2/peers/");
is($j->{"127.0.0.5:$port1"}{server}, 'baz.example.com:' . $port1,
	'baz in u2 is ok');


my $s = IO::Socket::INET->new(
	Proto    => 'tcp',
	PeerAddr => '127.0.0.1',
	PeerPort => port(8080)
)
	or die "cannot create socket: $!\n";

http_start(<<EOF, socket => $s);
GET /u2/slow HTTP/1.0
Host: localhost

EOF
my $s2 = IO::Socket::INET->new(
	Proto    => 'tcp',
	PeerAddr => '127.0.0.1',
	PeerPort => port(8080)
)
	or die "cannot create socket: $!\n";

http_start(<<EOF, socket => $s2);
GET /u2/slow HTTP/1.0
Host: localhost

EOF

# 2) wait for angie to connect to backends
select undef, undef, undef, 1;

$j = get_json("/api/status/http/upstreams/u2/peers/127.0.0.5:$port1");
is($j->{'refs'}, 2, "2 long requests to backend started, ref");

# 3) now delete corresponding DNS records:
#	- stop the DNS server
#	- restart it with new config without baz.example.com

$t->stop_resolver();

# start DNS server with new config, addresses changed
%addrs = (
    'foo.example.com' => ['127.0.0.3', '::1'],
    'bar.example.com' => ['127.0.0.4', '::1'],
);
my @nxservers = ('example.com');

$t->start_resolver(5353, \%addrs, {nxaddrs => \@nxaddrs,
	nxservers => \@nxservers});

# 4) wait for resolve timer to occure (resolver_timeout is 1s for u2)
select undef, undef, undef, 2;

$j = get_json("/api/status/http/upstreams/u2/zombies");
is($j, 1, "zombie found after name resolver dropped used peer");

http_end($s);
http_end($s2);

$j = get_json("/api/status/http/upstreams/u2/peers/127.0.0.5:$port1");
is($j->{error}, 'PathNotFound', "peer is deleted after resolve");

###############################################################################
