#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for updating http upstreams via Docker labels.

###############################################################################

use warnings;
use strict;

use Test::Deep qw/ deep_diag cmp_details superhashof /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

unless (caller) {
	my $t = Test::Nginx->new()
		->has(qw/http http_api upstream_zone docker upstream_sticky proxy/)
		->has(qw/stream stream_upstream_zone stream_upstream_sticky/);

	my $docker_helper = eval {
		Test::Docker->new({container_engine => 'docker'});
	};
	if ($@) {
		plan(skip_all => $@);
	}

	$t->write_file_expand('nginx.conf', prepare_config($docker_helper));

	my %test_cases = prepare_test_cases($docker_helper);

	$t->plan(scalar keys %test_cases);

	$t->run();

	$t->run_tests(\%test_cases);
}

###############################################################################

sub prepare_config {
	my $docker_helper = shift;

	return <<"EOF"
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint unix:$docker_helper->{endpoint};

    upstream u1 {
        zone http_z 1m;
    }

    upstream u2 {
        zone http_z;
    }

    server {
        listen %%PORT_8080%%;
        server_name localhost;

        location /api/ {
            api /;
        }

        location /pass1 {
            proxy_pass http://u1;
        }

        location /pass2 {
            proxy_pass http://u2;
        }

    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    upstream u1 {
        zone stream_z 1m;
    }

    upstream u2 {
        zone stream_z;
    }

    server {
        listen %%PORT_9090%%;
        server_name localhost;

        proxy_pass u1;
    }

    server {
        listen %%PORT_9091%%;
        server_name localhost;

        proxy_pass u2;
    }
}

EOF

}

sub prepare_test_cases {
	my $docker_helper = shift;

	my $container_engine = $docker_helper->{container_engine};

	return (
		"3 $container_engine containers" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 3},
		},
		"10 $container_engine containers" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 10},
		},
		"1 $container_engine container" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 1},
		},
		"15 $container_engine containers" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 15},
		},
		"4 $container_engine containers" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 4},
		},
		"30 $container_engine containers" => {
			test_sub    => \&test_containers,
			test_params => {docker_helper => $docker_helper, count => 30},
		},
	);
}

sub test_containers {
	my ($t, $test_params) = @_;

	my $docker_helper = $test_params->{docker_helper};

	# containers from the previous subtest may still exist
	$docker_helper->stop_containers();

	$docker_helper->start_containers($test_params->{count}, prepare_labels());

	my @ips = $docker_helper->get_container_ips();

	my %expected_peers = (
		http => {
			u1 => {
				80 => {sid => 'sid1', weight => 2, backup => JSON::false()},
			},
			u2 => {
				90 => {sid => 'sid2', weight => 5, backup => JSON::true()},
			},
		},
		stream => {
			u1 => {
				81 => {sid => 'sid3', weight => 10, backup => JSON::false()},
			},
			u2 => {
				91 => {sid => 'sid4', weight => 15, backup => JSON::true()},
			},
		},
	);

	my $expected;
	while (my ($type, $upstreams) = each %expected_peers) {
		while (my ($upstream_name, $upstream) = each %{ $upstreams }) {
			while (my ($port, $peer) = each %{ $upstream }) {
				foreach my $ip (@ips) {
					my $peer_addr = "$ip:$port";
					$expected->{$type}{$upstream_name}{$peer_addr} =
						superhashof({
							%{ $peer },
							server => $peer_addr,
							state  => 'up',
						});
				}
			}
		}
	}

	my $container_engine = $docker_helper->{container_engine};

	if (check_peers_created($container_engine, $expected)) {

		$docker_helper->pause_containers('pause');

		check_peers($container_engine, $expected, 'down');

		$docker_helper->pause_containers('unpause');

		check_peers($container_engine, $expected, 'up');
	}

	$docker_helper->stop_containers();
}

sub prepare_labels {
	my $labels = ' -l "angie.http.upstreams.u1.port=80"'
		. ' -l "angie.http.upstreams.u1.weight=2"'
		. ' -l "angie.http.upstreams.u1.max_conns=20"'
		. ' -l "angie.http.upstreams.u1.max_fails=5"'
		. ' -l "angie.http.upstreams.u1.fail_timeout=10s"'
		. ' -l "angie.http.upstreams.u1.slow_start=10s"'
		. ' -l "angie.http.upstreams.u1.backup=false"'
		. ' -l "angie.http.upstreams.u1.sid=sid1"'

		. ' -l "angie.http.upstreams.u2.port=90"'
		. ' -l "angie.http.upstreams.u2.weight=5"'
		. ' -l "angie.http.upstreams.u2.max_conns=25"'
		. ' -l "angie.http.upstreams.u2.max_fails=10"'
		. ' -l "angie.http.upstreams.u2.fail_timeout=5s"'
		. ' -l "angie.http.upstreams.u2.slow_start=5s"'
		. ' -l "angie.http.upstreams.u2.backup=true"'
		. ' -l "angie.http.upstreams.u2.sid=sid2"'

		. ' -l "angie.stream.upstreams.u1.port=81"'
		. ' -l "angie.stream.upstreams.u1.weight=10"'
		. ' -l "angie.stream.upstreams.u1.max_conns=20"'
		. ' -l "angie.stream.upstreams.u1.max_fails=5"'
		. ' -l "angie.stream.upstreams.u1.slow_start=15s"'
		. ' -l "angie.stream.upstreams.u1.fail_timeout=15s"'
		. ' -l "angie.stream.upstreams.u1.backup=false"'
		. ' -l "angie.stream.upstreams.u1.sid=sid3"'

		. ' -l "angie.stream.upstreams.u2.port=91"'
		. ' -l "angie.stream.upstreams.u2.weight=15"'
		. ' -l "angie.stream.upstreams.u2.max_conns=25"'
		. ' -l "angie.stream.upstreams.u2.max_fails=1"'
		. ' -l "angie.stream.upstreams.u2.slow_start=3s"'
		. ' -l "angie.stream.upstreams.u2.fail_timeout=3s"'
		. ' -l "angie.stream.upstreams.u2.backup=true"'
		. ' -l "angie.stream.upstreams.u2.sid=sid4"';

	return $labels;
}

sub check_peers_created {
	my ($container_engine, $expected) = @_;

	my ($ok, $stack, $got);

	for (0 .. 120) {
		my $api_status = get_json('/api/status/');

		foreach my $type (qw(http stream)) {
			my $upstreams = $api_status->{$type}{upstreams};
			while (my ($upstream_name, $upstream) = each %{ $upstreams }) {
				while (my ($peer_addr, $peer) = each %{ $upstream->{peers} }) {
					$got->{$type}{$upstream_name}{$peer_addr} = $peer;
				}
			}
		}

		($ok, $stack) = cmp_details($got, $expected);

		last if $ok;

		select undef, undef, undef, 0.5;
	}

	unless ($ok) {
		diag(deep_diag($stack));
		diag(explain({got => $got}));
	}

	return ok($ok, "all $container_engine peers created");
}

sub check_peers {
	my ($container_engine, $expected, $state_expected) = @_;

	my ($ok, $stack, $got);

	for (0 .. 120) {
		my $api_status = get_json('/api/status/');

		foreach my $type (qw(http stream)) {
			my $upstreams = $api_status->{$type}{upstreams};
			while (my ($upstream_name, $upstream) = each %{ $upstreams }) {
				while (my ($peer_addr, $peer) = each %{ $upstream->{peers} }) {
					$got->{$type}{$upstream_name}{$peer_addr} = $peer;
				}
			}
		}

		while (my ($type, $upstreams) = each %{ $expected }) {
			while (my ($upstream_name, $upstream) = each %{ $upstreams }) {
				while (my ($peer_addr, $peer) = each %{ $upstream }) {
					$peer->{val}{state} = $state_expected;
				}
			}
		}

		($ok, $stack) = cmp_details($got, $expected);

		last if $ok;

		select undef, undef, undef, 0.5;
	}

	unless ($ok) {
		diag(deep_diag($stack));
		diag(explain({got => $got}));
	}

	return ok($ok, "all $container_engine peers are $state_expected");
}

###############################################################################
