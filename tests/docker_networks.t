#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for Docker networks.

###############################################################################

use warnings;
use strict;

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
		->has(qw/http upstream_zone docker proxy http_api/);

	my $docker_helper_multi = eval {
		Test::Docker->new({
			container_engine => 'docker',
			networks => ['angie_net1', 'angie_net2', 'angie_net3']
		});
	};
	if ($@) {
		plan(skip_all => $@);
	}

	my $docker_helper_single = eval {
		Test::Docker->new({
			container_engine => 'docker',
			networks => ['angie_single_net']
		});
	};
	if ($@) {
		plan(skip_all => $@);
	}

	$t->write_file_expand('nginx.conf', prepare_config($docker_helper_multi));

	my %test_cases = prepare_test_cases(
		$docker_helper_multi, $docker_helper_single);

	$t->plan(scalar keys %test_cases);

	$t->run();

	$t->run_tests(\%test_cases);
}

###############################################################################

sub prepare_test_cases {
	my ($docker_helper_multi, $docker_helper_single) = @_;

	my $labels_multi = ' -l "angie.http.upstreams.angie_net1.port=8080"'
		. ' -l "angie.http.upstreams.angie_net1.network=angie_net1"'

		. ' -l "angie.http.upstreams.angie_net2.port=8080"'
		. ' -l "angie.http.upstreams.angie_net2.network=angie_net2"'

		. ' -l "angie.http.upstreams.angie_net3.port=8080"'
		. ' -l "angie.http.upstreams.angie_net3.network=angie_net3"';

	my $labels_single = ' -l "angie.http.upstreams.angie_single_net.port=8080"'
		. ' -l "angie.http.upstreams.angie_single_net.network=angie_single_net"'
		. ' -l "angie.network=angie_net1"';

	return (
		'several networks' => {
			test_sub    => \&test,
			test_params => {
				docker_helper => $docker_helper_multi,
				labels => $labels_multi
			},
		},
		'single network' => {
			test_sub    => \&test,
			test_params => {
				docker_helper => $docker_helper_single,
				labels => $labels_single
			},
		}
	);
}

sub test {
	my ($t, $test_params) = @_;

	my $docker_helper = $test_params->{docker_helper};
	my $labels = $test_params->{labels};

	$docker_helper->start_containers(5, $labels);

	check_peers($docker_helper);
}

###############################################################################

sub prepare_config {
	my ($docker_helper) = @_;

	return <<"EOF"
%%TEST_GLOBALS%%

daemon off;

events {
}

error_log %%TESTDIR%%/angie_docker.log notice;

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint unix:$docker_helper->{endpoint};

    upstream angie_net1 {
        zone z1 1m;
    }

    upstream angie_net2 {
        zone z2 1m;
    }

    upstream angie_net3 {
        zone z3 1m;
    }

    upstream angie_single_net {
        zone z4 1m;
    }

    server {
        listen %%PORT_8080%%;
        server_name localhost;

        location /pass {
            proxy_pass http://angie_net1;
        }

        location /api/ {
            api /;
        }
    }
}

EOF

}

sub check_peers {
	my ($docker_helper) = @_;

	my %networks = $docker_helper->get_container_networks();

	my $container_engine = $docker_helper->{container_engine};

	foreach my $network (keys %networks) {
		my @ips = @{$networks{$network}};

		my $url = "/api/status/http/upstreams/$network/peers";
		my $peers = get_json($url);

		for my $ip (@ips) {
			my $peer = "$ip:8080";

			for (1 .. 120) {
				last if exists $peers->{$peer};

				$peers = get_json($url);
				select undef, undef, undef, 0.5;
			}

			is($peers->{$peer}{server}, $peer,
				"$container_engine peer '$peer' created in network $network");
		}
	}
}

###############################################################################
