#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for stream upstream least_time balancer module.

###############################################################################

use warnings;
use strict;

use Test::Deep qw/cmp_deeply cmp_details deep_diag/;
use Test::More;
use IO::Socket qw/SHUT_WR/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json socket_read :log :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant REQUESTS => 100;

my $t = Test::Nginx->new()
	->has(qw/stream stream_upstream_least_time stream_upstream_zone/)
	->has(qw/http http_api/);

my ($p1, $p2) = (8081, 8082);
my ($port1, $port2) = (port($p1), port($p2));

my $i = 1;
my $port = 8091;

my %test_cases;

foreach my $factors (['', ''], ['80', ''], ['', '80'], ['80', '10']) {
	my ($factor, $rt_factor) = @{ $factors };

	my $factor_str = $factor ? " factor=$factor" : '';

	# we can't control the connect time,
	# so we do not check requests distribution here
	$test_cases{"connect, factor=$factor, rt_factor=$rt_factor"} = {
		config => {
			stream => {
				upstream => [{
					name     => "u$i-connect",
					zone     => "z$i 128k",
					balancer => 'least_time connect' . $factor_str,
					($rt_factor) ? (response_time_factor => $rt_factor) : (),
					server   => [
						"127.0.0.1:$p1",
						"127.0.0.1:$p2",
					],
				}],
				server => [{
					listen     => "127.0.0.1:$port",
					proxy_pass => "u$i-connect",
				}],
			},
		},
		test_sub    => \&test_balancer,
		test_params => {
			port          => port($port),
			upstream_name => "u$i-connect",
			expected      => {},
		},
	};
	$i++;
	$port++;

	$test_cases{"first_byte, factor=$factor, rt_factor=$rt_factor"} = {
		config => {
			stream => {
				upstream => [{
					name     => "u$i-first_byte",
					zone     => "z$i 128k",
					balancer => 'least_time first_byte' . $factor_str,
					($rt_factor) ? (response_time_factor => $rt_factor) : (),
					server   => [
						"127.0.0.1:$p1", # slow
						"127.0.0.1:$p2", # fast
					],
				}],
				server => [{
					listen     => "127.0.0.1:$port",
					proxy_pass => "u$i-first_byte",
				}],
			},
		},
		test_sub    => \&test_balancer,
		test_params => {
			port          => port($port),
			upstream_name => "u$i-first_byte",
			input         => 'first',
			expected      => {
				requests => [$port1, $port2],
				api => sub {
					my $got = shift;

					# expected:
					#	p1:
					#		connect_time    => 1
					#		first_byte_time => 50
					#		last_byte_time  => 50
					#	$p2:
					#		connect_time    => 1
					#		first_byte_time => 1
					#		last_byte_time  => 1

					return (0, "$port1: first_byte_time < 50 (delay)")
						if $got->{$port1}{first_byte_time} < 50;

					return (0, "$port1: last_byte_time < 50 (delay)")
						if $got->{$port1}{last_byte_time} < 50;

					return (0, "$port2 last_byte_time > $port1 last_byte_time")
						if ($got->{$port2}{last_byte_time} - $got->{$port2}{connect_time})
							> ($got->{$port1}{last_byte_time} - $got->{$port1}{connect_time});

					return 1;
				},
			},
		},
	};
	$i++;
	$port++;

	$test_cases{"first_byte reversed order, factor=$factor, rt_factor=$rt_factor"} = {
		config => {
			stream => {
				upstream => [{
					name     => "u$i-first_byte-reversed",
					zone     => "z$i 128k",
					balancer => 'least_time first_byte' . $factor_str,
					($rt_factor) ? (response_time_factor => $rt_factor) : (),
					server   => [
						"127.0.0.1:$p2", # fast
						"127.0.0.1:$p1", # slow
					],
				}],
				server => [{
					listen     => "127.0.0.1:$port",
					proxy_pass => "u$i-first_byte-reversed",
				}],
			},
		},
		test_sub    => \&test_balancer,
		test_params => {
			port          => port($port),
			upstream_name => "u$i-first_byte-reversed",
			input         => 'first',
			expected      => {
				requests => [$port1, $port2],
				api => sub {
					my $got = shift;

					# expected:
					#	p1:
					#		connect_time    => 1
					#		first_byte_time => 50
					#		last_byte_time  => 50
					#	p2:
					#		connect_time    => 1
					#		first_byte_time => 1
					#		last_byte_time  => 1

					return (0, "$port1: first_byte_time < 50 (delay)")
						if $got->{$port1}{first_byte_time} < 50;

					return (0, "$port1: last_byte_time < 50 (delay)")
						if $got->{$port1}{last_byte_time} < 50;

					return (0, "$port2 last_byte_time > $port1 last_byte_time")
						if ($got->{$port2}{last_byte_time} - $got->{$port2}{connect_time})
							> ($got->{$port1}{last_byte_time} - $got->{$port1}{connect_time});

					return 1;
				},
			},
		},
	};
	$i++;
	$port++;

	$test_cases{"last_byte, factor=$factor, rt_factor=$rt_factor"} = {
		config => {
			stream => {
				upstream => [{
					name     => "u$i-last_byte",
					zone     => "z$i 128k",
					balancer => 'least_time last_byte' . $factor_str,
					($rt_factor) ? (response_time_factor => $rt_factor) : (),
					server   => [
						"127.0.0.1:$p1", # slow
						"127.0.0.1:$p2", # fast
					],
				}],
				server => [{
					listen     => "127.0.0.1:$port",
					proxy_pass => "u$i-last_byte",
				}],
			},
		},
		test_sub    => \&test_balancer,
		test_params => {
			port          => port($port),
			upstream_name => "u$i-last_byte",
			input         => 'last',
			expected      => {
				requests => [$port1, $port2],
				api => sub {
					my $got = shift;

					# expected:
					#	p1:
					#		connect_time    => 1
					#		first_byte_time => 1
					#		last_byte_time  => 50
					#	p2:
					#		connect_time    => 1
					#		first_byte_time => 1
					#		last_byte_time  => 1

					return (0, "$port1: last_byte_time < 50 (delay)")
						if $got->{$port1}{last_byte_time} < 50;

					return (0, "$port2 last_byte_time > $port1 last_byte_time")
						if ($got->{$port2}{last_byte_time} - $got->{$port2}{connect_time})
							> ($got->{$port1}{last_byte_time} - $got->{$port1}{connect_time});

					return 1;
				},
			},
		},
	};
	$i++;
	$port++;

	$test_cases{"last_byte reversed order, factor=$factor, rt_factor=$rt_factor"} = {
		config => {
			stream => {
				upstream => [{
					name     => "u$i-last_byte-reversed",
					zone     => "z$i 128k",
					balancer => 'least_time last_byte' . $factor_str,
					($rt_factor) ? (response_time_factor => $rt_factor) : (),
					server   => [
						"127.0.0.1:$p2", # fast
						"127.0.0.1:$p1", # slow
					],
				}],
				server => [{
					listen     => "127.0.0.1:$port",
					proxy_pass => "u$i-last_byte-reversed",
				}],
			},
		},
		test_sub    => \&test_balancer,
		test_params => {
			port          => port($port),
			upstream_name => "u$i-last_byte-reversed",
			input         => 'last',
			expected      => {
				requests => [$port1, $port2],
				api => sub {
					my $got = shift;

					# expected
					#	p1:
					#		connect_time    => 1,
					#		first_byte_time => 1,
					#		last_byte_time  => 50,
					#	p2:
					#		connect_time    => 1,
					#		first_byte_time => 1,
					#		last_byte_time  => 1,

					return (0, "$port1: last_byte_time < 50 (delay)")
						if $got->{$port1}{last_byte_time} < 50;

					return (0, "$port2: connect_time > first_byte_time")
						if $got->{$port2}{connect_time}
							> $got->{$port2}{first_byte_time};

					return (0, "$port2 last_byte_time > $port1 last_byte_time")
						if $got->{$port2}{last_byte_time}
							> $got->{$port1}{last_byte_time};

					return 1;
				},
			},
		},
	};
	$i++;
	$port++;
};

$t->{config} = Test::Nginx::Config->new();
$t->{config}->add_api_server();

$t->prepare_config(\%test_cases);

my $config_string = $t->{config}->convert_to_string();

$t->write_file_expand('nginx.conf', $config_string);

foreach my $port ($port1, $port2) {
	local $@;
	eval {
		$t->run_daemon(\&stream_daemon, $port);
	};
	die "Can't start daemon on port $port: $@" if $@;

	eval {
		$t->waitforsocket('127.0.0.1:' . $port);
	};
	if ($@) {
		die "Can't start daemon on port $port: $@";
	}
	note("running daemon on port $port");
}

$t->plan(scalar keys %test_cases);

$t->run();

$t->run_tests(\%test_cases);

###############################################################################

sub test_balancer {
	my ($t, $test_params) = @_;

	my $balancer_stat = collect_balancer_stat($test_params);

	my $expected = $test_params->{expected};

	if (defined $expected->{requests}) {
		my @requests_share = sort {
			$balancer_stat->{$a} <=> $balancer_stat->{$b}
		} keys %{ $balancer_stat };

		cmp_deeply(\@requests_share, $expected->{requests},
			'distibution of requests across peers')
			or diag(explain({
				got => \@requests_share,
				expected => $expected->{requests},
				balancer_stat => $balancer_stat
			}));
	}

	my $api_stat = collect_api_stat($test_params->{upstream_name});

	cmp_deeply($api_stat->{requests}, $balancer_stat, 'requests api stat')
		or diag(explain({
			api_requests      => $api_stat->{requests},
			balancer_requests => $balancer_stat,
		}));

	my ($api_ok, $reason) = test_api_response($api_stat->{health},
		$expected->{api});
	ok($api_ok, 'health api stat')
		or diag(explain({
			health_got => $api_stat->{health},
			reason => $reason
		}));
}

sub test_api_response {
	my ($got, $expected) = @_;

	my $expected_api = {
		$port1 => {
			connect_time    => $NUM_RE,
			first_byte_time => $NUM_RE,
			last_byte_time  => $NUM_RE,
		},
		$port2 => {
			connect_time    => $NUM_RE,
			first_byte_time => $NUM_RE,
			last_byte_time  => $NUM_RE,
		}
	};
	my ($ok, $stack) = cmp_details($got, $expected_api);
	return (0, deep_diag($stack))
		unless $ok;

	return (0, "$port1: connect_time > first_byte_time")
		if $got->{$port1}{connect_time} > $got->{$port1}{first_byte_time};

	return (0, "$port1: first_byte_time > last_byte_time")
		if $got->{$port1}{first_byte_time} > $got->{$port1}{last_byte_time};

	return (0, "$port2: connect_time > first_byte_time")
		if $got->{$port2}{connect_time} > $got->{$port2}{first_byte_time};

	return (0, "$port2: first_byte_time > last_byte_time")
		if $got->{$port2}{first_byte_time} > $got->{$port2}{last_byte_time};

	if (defined $expected && ref $expected eq 'CODE') {
		return $expected->($got);
	}

	return 1;
}

###############################################################################

sub collect_balancer_stat {
	my $test_params = shift;

	my %balancer_stat;
	my $input = ($test_params->{input} // '.') . '$';

	note("\n");

	for my $i (1 .. REQUESTS) {

		my $output = stream('127.0.0.1:' . $test_params->{port})->io($input);
		note($i . ": $input -> $output");

		if ($output && $output =~ /^(\d{4})/m) {
			my $port = $1;

			$balancer_stat{$port} //= 0;
			$balancer_stat{$port}++;

			my $stat = get_json('/api/status/stream/upstreams/'
				. "$test_params->{upstream_name}/peers/127.0.0.1:$port");
			note("test_case\t$test_params->{test_case_name}#$i\t$port\t"
				. "connect=$stat->{health}{connect_time}\t"
				. "first_byte=$stat->{health}{first_byte_time}\t"
				. "last_byte=$stat->{health}{last_byte_time}"
			);
			note("\n");

		} else {
			note($i . ": $input -> $output");
			diag("not registered request: '$input -> $output'");
		}
	}

	note(explain({balancer_stat => \%balancer_stat}));

	return \%balancer_stat;
}

sub collect_api_stat {
	my $upstream_name = shift;

	my $stat = get_json("/api/status/stream/upstreams/$upstream_name/peers/");
	note(explain({full_stat => $stat}));

	my %api_stat;
	while (my ($peer, $peer_stat) = each (%{ $stat })) {
		(my $port) = $peer =~ /^127\.0\.0\.1:(\d+)$/;

		$api_stat{requests}{$port} = $peer_stat->{selected}{total};

		$api_stat{health}{$port}{$_} = $peer_stat->{health}{$_}
			for qw(connect_time first_byte_time last_byte_time);
	}

	note(explain({api_stat => \%api_stat}));

	return \%api_stat;
}

sub stream_daemon {
	my $port = shift;

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Listen    => 5,
		Reuse     => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $input = socket_read($client, trailing_char => '$');
		next unless $input;

		my $client_port = $client->sockport();
		log2c("(new connection to $client_port)");

		log2i("$client_port $input");

		my $output = $client_port;

		if ($client_port == $port1 && $input ne '.$') {

			# to shift last_byte_time: send first part, wait, send the rest data
			print $client $output
				if $input eq 'last$';

			select undef, undef, undef, 0.05;

			# to shift first_byte_time: wait, send all data
			print $client $output
				if $input eq 'first$';

			log2o("$client_port $output");
		}

		print $client $output;
		log2o("$client_port $output");

		$client->shutdown(SHUT_WR);
		log2c("(connection to $client_port closed)")
	}
}
