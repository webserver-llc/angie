#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for stream upstream statistics.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply superhashof/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json :log :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/stream stream_upstream_zone http http_api/)
	->plan(5)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /status/ {
            api /status/stream/;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    upstream u {
        zone z 1m;
        server 127.0.0.1:8091;
        server 127.0.0.1:8092;
        server 127.0.0.1:8093 weight=32 down backup max_fails=5 max_conns=7;
    }

    upstream f {
        zone zk 1m;

        server 127.0.0.1:8091 backup;
        server 127.0.0.1:8093 fail_timeout=1s;
    }

    upstream fd {
        zone zk 1m;

        server 127.0.0.1:8094 fail_timeout=1s;
    }

    server {
        listen       127.0.0.1:8081;
        proxy_pass   u;
    }

    server {
        listen       127.0.0.1:8082;
        proxy_pass   f;
    }

    server {
        listen       127.0.0.1:8083;
        proxy_pass   fd;
    }
}

EOF

my ($port1, $port2, $port3, $port4)
	= (port(8091), port(8092), port(8093), port(8094));

$t->run_daemon(\&stream_daemon, $port1);
$t->run_daemon(\&stream_daemon, $port2);

$t->run();

$t->waitforsocket('127.0.0.1:' . $port1);
$t->waitforsocket('127.0.0.1:' . $port2);

###############################################################################

subtest 'peer selection statistics' => sub {
	# give 1 request for each backend
	stream('127.0.0.1:' . port(8081))->io('.') for 1..2;

	my $j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/selected/");
	cmp_deeply($j, {current => 0, total => 1, last => $TIME_RE},
		'b1 initial number of connections');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port2/selected/");
	cmp_deeply($j, {current => 0, total => 1, last => $TIME_RE},
		'b2 initial number of connections');

	# issue 4 requests to update counters
	stream('127.0.0.1:' . port(8081))->io('.') for 1..4;

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/selected/");
	cmp_deeply($j, {current => 0, total => 3, last => $TIME_RE},
		'b1 new number of connections');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port2/selected/");
	cmp_deeply($j, {current => 0, total => 3, last => $TIME_RE},
		'b2 new number of connections');

	# current connections
	my @s;
	for (1..2) {
		my $s = stream('127.0.0.1:' . port(8081));
		$s->write('keep');
		$s->read();
		push @s, $s;
	}

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port1/selected/");
	cmp_deeply($j, {current => 1, total => 4, last => $TIME_RE},
		'b1 new number of connections (current)');

	$j = get_json("/status/upstreams/u/peers/127.0.0.1:$port2/selected/");
	cmp_deeply($j, {current => 1, total => 4, last => $TIME_RE},
		'b2 new number of connections (current)');
};

subtest 'verify peer properties' => sub {
	my $j = get_json("/status/upstreams/u/peers/127.0.0.1:$port3/");

	my $expected_properties = {
		server    => "127.0.0.1:$port3",
		weight    => 32,
		state     => 'down',
		max_conns => 7,
		backup    => JSON::true(),
		data      => {sent => 0, received => 0},
		selected  => {current => 0, total => 0},
		health    => {unavailable => 0, downtime => 0, fails => 0},
	};

	cmp_deeply($j, superhashof($expected_properties), 'peer b3 properties');
};

subtest 'verify upstream properties' => sub {
	my $j = get_json('/status/upstreams/u/');

	SKIP: {
		skip 'requires debug', 1
			unless $t->has_module('debug');

		is($j->{zone}, 'z', 'configured zone');
	}

	is(keys %{ $j->{peers} }, 3, '3 peers in upstream');
};

subtest 'verify peer fails' => sub {

	# this goes to b3, fails, then to b1
	stream('127.0.0.1:' . port(8082))->io('.');

	my $j = get_json('/status/upstreams/f/peers');

	my $b3 = $j->{"127.0.0.1:$port3"};
	is($b3->{state}, 'unavailable', 'b3 is unavailable');
	is($b3->{selected}{total},   1, 'b3 selected incremented');

	is($b3->{health}{fails},       1, 'b3 fails incremented');
	is($b3->{health}{unavailable}, 1, 'b3 unavailable incremented');
	cmp_deeply($b3->{health}{downstart}, $TIME_RE, 'b3 defined downstart');

	my $b1 = $j->{"127.0.0.1:$port1"};
	is($b1->{state},        'up', 'b1 is up');
	is($b1->{selected}{total}, 1, 'b1 selected incremented');

	is($b1->{health}{fails},         0, 'b1 zero fails');
	is($b1->{health}{unavailable},   0, 'b1 zero unavailable');
	is($b1->{health}{downstart}, undef, 'b1 not defined downstart');
	is($b1->{health}{downtime},      0, 'b1 zero downtime');

	# wait a bit to get downtime incremented
	# TODO: avoid delay
	select undef, undef, undef, 0.5;

	$j = get_json("/status/upstreams/f/peers/127.0.0.1:$port3/health/downtime");
	ok($j > 0, 'b3 nonzero downtime');

	# revive peer
	$t->run_daemon(\&stream_daemon, $port3);
	$t->waitforsocket('127.0.0.1:' . $port3);

	# wait till fail_timeout passes
	select undef, undef, undef, 1.5;

	stream('127.0.0.1:' . port(8082))->io('.') for 1..5;

	$j = get_json('/status/upstreams/f/peers');

	# all requests must go to b3

	$b3 = $j->{"127.0.0.1:$port3"};
	is($b3->{state},        'up', 'b3 is up again');
	is($b3->{selected}{total}, 6, 'b3 selected incremented');

	is($b3->{health}{fails},         1, 'b3 fails not incremented');
	is($b3->{health}{unavailable},   1, 'b3 unavailable not incremented');
	is($b3->{health}{downstart}, undef, 'b3 not defined downstart');
	ok($b3->{health}{downtime} > 0,     'b3 nonzero downtime');

	$b1 = $j->{"127.0.0.1:$port1"};
	is($b1->{state},        'up', 'b1 is up');
	is($b1->{selected}{total}, 1, 'b1 selected not incremented');

	is($b1->{health}{fails},         0, 'b1 zero fails');
	is($b1->{health}{unavailable},   0, 'b1 zero unavailable');
	is($b1->{health}{downstart}, undef, 'b1 not defined downstart');
	is($b1->{health}{downtime},      0, 'b1 zero downtime');

	# check that downtime stopped growing
	my $downtime = $j->{"127.0.0.1:$port3"}{health}{downtime};

	# wait a bit
	select undef, undef, undef, 1;

	$j = get_json("/status/upstreams/f/peers/127.0.0.1:$port3/health/downtime");
	is($j, $downtime, 'b3 downtime stopped growing');
};

subtest 'fail with open connection' => sub {
	my $s = stream('127.0.0.1:' . port(8083));
	$s->write('keep');

	# wait a bit to get downtime incremented
	# TODO: avoid delay
	select undef, undef, undef, 0.5;

	my $j = get_json("/status/upstreams/fd/peers/127.0.0.1:$port4/");

	is($j->{state}, 'unavailable', 'b4 is unavailable');
	is($j->{selected}{total},   1, 'b4 selected incremented');
	is($j->{selected}{current}, 0, 'b4 zero current');

	is($j->{health}{fails},       1, 'b4 fails incremented');
	is($j->{health}{unavailable}, 1, 'b4 unavailable incremented');
	cmp_deeply($j->{health}{downstart}, $TIME_RE, 'b4 not empty downstart');
	ok($j->{health}{downtime} > 0,   'b4 nonzero downtime');

	# revive peer
	$t->run_daemon(\&stream_daemon, $port4);
	$t->waitforsocket('127.0.0.1:' . $port4);

	# wait till fail_timeout passes
	select undef, undef, undef, 1.5;

	$s = stream('127.0.0.1:' . port(8083));
	$s->write('keep');
	$s->read();

	$j = get_json("/status/upstreams/fd/peers/127.0.0.1:$port4/");

	is($j->{state},          'up', 'b4 is up');
	is($j->{selected}{total},   2, 'b4 selected incremented');
	is($j->{selected}{current}, 1, 'b4 current incremented');

	is($j->{health}{fails},         1, 'b4 fails not incremented');
	is($j->{health}{unavailable},   1, 'b4 unavailable not incremented');
	is($j->{health}{downstart}, undef, 'b4 not defined downstart');
	ok($j->{health}{downtime} > 0,     'b4 non zero downtime');

	# check that downtime stopped growing
	my $downtime = $j->{health}{downtime};

	# wait a bit
	select undef, undef, undef, 1;

	$j = get_json("/status/upstreams/fd/peers/127.0.0.1:$port4/health/downtime");
	is($j, $downtime, 'b4 downtime stopped growing');
};

###############################################################################

sub stream_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($server);

	local $SIG{PIPE} = 'IGNORE';

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($server == $fh) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif (stream_handle_client($fh)) {
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub stream_handle_client {
	my ($client) = @_;

	log2c("(new connection $client)");

	$client->sysread(my $buffer, 65536) or return 1;

	log2i("$client $buffer");

	my $close = $buffer ne 'keep';
	$buffer = $client->sockport();

	log2o("$client $buffer");

	$client->syswrite($buffer);

	return $close;
}

