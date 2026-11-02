#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for stream upstream statistics.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply superhashof ignore/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json get_json_stable :log :re/;

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

# Under load the event that records a change in the peer statistics and
# the api request that observes it can be processed within one event loop
# iteration: the snapshot then shows stale counters, and values computed
# from timestamps ("downtime") come out as zero because both timestamps
# are taken from the same cached time.  Snapshots that follow an event
# are therefore polled until they show the expected values, turning the
# checks into conditions rather than moments.  The expected values are
# still asserted below: a wrong value simply never settles and fails the
# check once the retries are exhausted.

subtest 'peer selection statistics' => sub {
	# give 1 request for each backend
	stream('127.0.0.1:' . port(8081))->io('.') for 1..2;

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port1/selected/",
		{current => 0, total => 1, last => $TIME_RE},
		'b1 initial number of connections');

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port2/selected/",
		{current => 0, total => 1, last => $TIME_RE},
		'b2 initial number of connections');

	# issue 4 requests to update counters
	stream('127.0.0.1:' . port(8081))->io('.') for 1..4;

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port1/selected/",
		{current => 0, total => 3, last => $TIME_RE},
		'b1 new number of connections');

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port2/selected/",
		{current => 0, total => 3, last => $TIME_RE},
		'b2 new number of connections');

	# current connections
	my @s;
	for (1..2) {
		my $s = stream('127.0.0.1:' . port(8081));
		$s->write('keep');
		$s->read();
		push @s, $s;
	}

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port1/selected/",
		{current => 1, total => 4, last => $TIME_RE},
		'b1 new number of connections (current)');

	get_json_stable(
		"/status/upstreams/u/peers/127.0.0.1:$port2/selected/",
		{current => 1, total => 4, last => $TIME_RE},
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
		health    => {
			unavailable => 0, downtime => 0, fails => 0,
			connect_time => $NUM_RE, first_byte_time => $NUM_RE,
			last_byte_time => $NUM_RE
		},
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

	get_json_stable(
		'/status/upstreams/f/peers',
		{
			"127.0.0.1:$port1" => superhashof({
				state    => 'up',
				selected => superhashof({total => 1}),
				health   => {
					fails => 0, unavailable => 0, downtime => 0,
					connect_time => ignore(), first_byte_time => ignore(),
					last_byte_time => ignore()
				}
			}),
			"127.0.0.1:$port3" => superhashof({
				state    => 'unavailable',
				selected => superhashof({total => 1}),
				health   => {
					fails => 1, unavailable => 1, downtime => $NUM_RE,
					downstart => $TIME_RE,
					connect_time => ignore(), first_byte_time => ignore(),
					last_byte_time => ignore()
				},
			}),
		},
		'b1 and b3 metrics: b3 is down');

	# downtime accumulates while the peer is down
	get_json_stable(
		"/status/upstreams/f/peers/127.0.0.1:$port3/health/downtime",
		$POSITIVE_NUM,
		'b3 nonzero downtime');

	# revive peer
	$t->run_daemon(\&stream_daemon, $port3);
	$t->waitforsocket('127.0.0.1:' . $port3);

	# wait till fail_timeout passes; the failure itself may have been
	# recorded late under load, and the polls above already waited for
	# it, so this margin is measured from the recorded failure
	select undef, undef, undef, 3;

	stream('127.0.0.1:' . port(8082))->io('.') for 1..5;

	# all requests must go to 3
	my $j = get_json_stable(
		'/status/upstreams/f/peers',
		{
			"127.0.0.1:$port1" => superhashof({
				state    => 'up',
				selected => superhashof({total => 1}),
				health   => {
					fails => 0, unavailable => 0, downtime => 0,
					connect_time => ignore(), first_byte_time => ignore(),
					last_byte_time => ignore()
				},
			}),
			"127.0.0.1:$port3" => superhashof({
				state    => 'up',
				selected => superhashof({total => 6}),
				health   => {
					fails => 1, unavailable => 1, downtime => $POSITIVE_NUM,
					connect_time => ignore(), first_byte_time => ignore(),
					last_byte_time => ignore()
				},
			}),
		},
		'b1 and b3 metrics: b3 is up again'
	);

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

	get_json_stable(
		"/status/upstreams/fd/peers/127.0.0.1:$port4/",
		superhashof({
			state    => 'unavailable',
			selected => superhashof({total => 1, current => 0}),
			health   => superhashof({
				fails => 1, unavailable => 1, downstart => $TIME_RE,
				downtime => $POSITIVE_NUM
			}),
		}),
		'b4 metrics: down');

	# revive peer
	$t->run_daemon(\&stream_daemon, $port4);
	$t->waitforsocket('127.0.0.1:' . $port4);

	# wait till fail_timeout passes; see the comment in the previous
	# subtest about the margin
	select undef, undef, undef, 3;

	$s = stream('127.0.0.1:' . port(8083));
	$s->write('keep');
	$s->read();

	my $j = get_json_stable(
		"/status/upstreams/fd/peers/127.0.0.1:$port4/",
		superhashof({
			state    => 'up',
			selected => superhashof({total => 2, current => 1}),
			health   => {
				fails => 1, unavailable => 1, downtime => $POSITIVE_NUM,
				connect_time => ignore(), first_byte_time => ignore(),
				last_byte_time => ignore()
			},
		}),
		'b4 metrics: up');

	# check that downtime stopped growing
	my $downtime = $j->{health}{downtime};

	# wait a bit
	select undef, undef, undef, 1;

	$j = get_json(
		"/status/upstreams/fd/peers/127.0.0.1:$port4/health/downtime");
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

