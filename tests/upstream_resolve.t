#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for upstream re-resolve.

###############################################################################

use warnings;
use strict;
#use Data::Dumper;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/http_start port http_get http_end/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

# the test depends on availability of 127.0.0.0/8 subnet on targets
plan(skip_all => 'OS is not linux') if $^O ne 'linux';

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone --with-debug/)
	->has_daemon("dnsmasq");

# see https://trac.nginx.org/nginx/ticket/1831
plan(skip_all => "perl >= 5.32 required") if ($t->has_module('perl') && $] < 5.032000);

$t->plan(14)->write_file_expand('nginx.conf', <<'EOF');

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

        resolver 127.0.0.1:5353 valid=1s;
    }

    upstream u2 {
        zone z 1m;
        server baz.example.com:%%PORT_8081%% resolve;

        resolver 127.0.0.1:5353 valid=1s ipv6=off;
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

my $tdir = $t->testdir();

# TODO: use substituted ports for parallel execution for DNS server
$t->write_file_expand('dns.conf', <<'EOF');
# listen on this port
port=5353
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this fil
addn-hosts=%%TESTDIR%%/test_hosts
EOF

$t->write_file_expand('dns2.conf', <<'EOF');
# listen on this port
port=5353
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this fil
addn-hosts=%%TESTDIR%%/test_hosts2
# return NXDOMAIN for this
address=/backup.example.com/
EOF

$t->write_file_expand('dns3.conf', <<'EOF');
# listen on this port
port=5353
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this fil
addn-hosts=%%TESTDIR%%/test_hosts3
# return NXDOMAIN for this
address=/backup.example.com/
EOF


# ipv6 entries are stubs for resolver
$t->write_file_expand('test_hosts', <<'EOF');
127.0.0.1  foo.example.com
127.0.0.2  bar.example.com
127.0.0.3  backup.example.com
127.0.0.4  backup.example.com
127.0.0.5  baz.example.com
::1 foo.example.com
::1 bar.example.com
::1 backup.example.com
::1 baz.example.com
EOF

$t->write_file_expand('test_hosts2', <<'EOF');
127.0.0.3  foo.example.com
127.0.0.4  bar.example.com
127.0.0.5  baz.example.com
::1 foo.example.com
::1 bar.example.com
::1 baz.example.com
EOF

$t->write_file_expand('test_hosts3', <<'EOF');
127.0.0.3  foo.example.com
127.0.0.4  bar.example.com
::1 foo.example.com
::1 bar.example.com
EOF

my $dconf = $t->testdir()."/dns.conf";

$t->run_daemon('dnsmasq', '-C', $tdir."/dns.conf", '-k', "--log-facility=$tdir/dns.log", '-q');

# let the dnsmasq execute;

$t->run();

###############################################################################

my @ports = my ($port1, $port2) = (port(8081), port(8082));

my ($j, $v);

# give 1 request for each backend (note: due to IPv6 there may be 4 peers)
http_get('/'); http_get('/');

# expect that upstream contains addresses from 'test_hosts' file

$j = get_json("/api/status/http/upstreams/u/peers/");

my $n4 = 0;

foreach my $addr ( keys %$j ) {

    #print(Dumper($j->{$addr}));

    if ($addr eq "127.0.0.1:$port1") {
        $n4 = $n4 + 1;
        is($j->{$addr}->{'server'}, 'foo.example.com:'.$port1, 'foo.example.com is resolved');
    }

    if ($addr eq "127.0.0.2:$port2") {
        $n4 = $n4 + 1;
        is($j->{$addr}->{'server'}, 'bar.example.com:'.$port2, 'bar.example.com resolved');
    }

    if ($addr eq "127.0.0.3:$port1") {
        is($j->{$addr}->{'server'}, 'backup.example.com:'.$port1, 'backup.example.com addr 1 resolved');
    }

    if ($addr eq "127.0.0.4:$port1") {
        is($j->{$addr}->{'server'}, 'backup.example.com:'.$port1, 'backup.example.com addr 2 resolved');
    }
}

is($n4, 2, 'foo and bar.example.com resolved into 2 ipv4 addresses');


# perform reload to trigger the codepath for pre-resolve
$t->reload();
small_delay();

$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.1:$port1"}->{'server'}, "foo.example.com:$port1", 'foo.example.com is found after reload');
is($j->{"127.0.0.2:$port2"}->{'server'}, "bar.example.com:$port2", 'bar.example.com is found after reload');


# now stop DNS daemon to prevent resolving, reload nginx
# and verify upstreams are still accessible

$t->stop_daemons();
$t->reload();
small_delay();

$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.1:$port1"}->{'server'}, "foo.example.com:$port1", 'foo.example.com is saved');
is($j->{"127.0.0.2:$port2"}->{'server'}, "bar.example.com:$port2", 'bar.example.com is saved');


# start DNS server with new config, addresses changed
$t->run_daemon('dnsmasq', '-C', $tdir."/dns2.conf", '-k', "--log-facility=$tdir/dns.log", '-q');
# reload nginx to force resolve
$t->reload();
# wait 3 seconds to ensure re-resolve (valid=1s)
select undef, undef, undef, 3;

# expect 127.0.0.3 is now foo instead of 'backup'
$j = get_json("/api/status/http/upstreams/u/peers/");
is($j->{"127.0.0.3:$port1"}->{'server'}, "foo.example.com:$port1", 'foo.example.com is new');
is($j->{"127.0.0.4:$port2"}->{'server'}, "bar.example.com:$port2", 'bar.example.com is new');

# TODO: actually trigger zombies; currently test verifies refcount with debug
trigger_zombies();

sub trigger_zombies {

    $j = get_json("/api/status/http/upstreams/u2/peers/");
    is($j->{"127.0.0.5:$port1"}->{'server'}, 'baz.example.com:'.$port1, 'baz in u2 is ok');


    my $s = IO::Socket::INET->new(Proto => 'tcp',
                                  PeerAddr => '127.0.0.1',
                                  PeerPort => port(8080))
    or die "cannot create socket: $!\n";

    http_start(<<EOF, socket => $s);
GET /u2/slow HTTP/1.0
Host: localhost

EOF
    my $s2 = IO::Socket::INET->new(Proto => 'tcp',
                                  PeerAddr => '127.0.0.1',
                                  PeerPort => port(8080))
    or die "cannot create socket: $!\n";

    http_start(<<EOF, socket => $s2);
GET /u2/slow HTTP/1.0
Host: localhost

EOF

    small_delay();

    $j = get_json("/api/status/http/upstreams/u2/peers/127.0.0.5:$port1");
    is($j->{'refs'}, 2, "2 long requests to backend started, ref");

    my $res = http_end($s);
    my $res2 = http_end($s2);

    $j = get_json("/api/status/http/upstreams/u2/peers/127.0.0.5:$port1");
    is($j->{'refs'}, 0, "2 long requests to backend completed, unref");
}

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

sub wait_for_dns {
    # TODO: waitport() for UDP sockets; avoid delay
    select undef, undef, undef, 2;
}

sub small_delay {
    select undef, undef, undef, 1;
}
