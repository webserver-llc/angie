#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for containers count for the default buffer.

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
		->has(qw/http http_api upstream_zone docker proxy/);

	my $docker_helper = eval {
		Test::Docker->new({container_engine => 'docker'});
	};
	if ($@) {
		plan(skip_all => $@);
	}

	$t->plan(27)
		->write_file_expand('nginx.conf', prepare_config($docker_helper));

	test($t, $docker_helper);
}

###############################################################################

sub test {
	my ($t, $docker_helper) = @_;

	my $labels = ' -l "angie.http.upstreams.u.port=80"'
		. ' -l "angie.http.upstreams.u.weight=2"'
		. ' -l "angie.http.upstreams.u.max_conns=20"'
		. ' -l "angie.http.upstreams.u.max_fails=5"'
		. ' -l "angie.http.upstreams.u.slow_start=10s"'
		. ' -l "angie.http.upstreams.u.fail_timeout=10s"'
		. ' -l "angie.http.upstreams.u.backup=false"'
		. ' -l "angie.http.upstreams.u.sid=sid1"';

	$docker_helper->start_containers(25, $labels);

	$t->run();

	check_peers($docker_helper);

	$t->stop();

	check_log($t, $docker_helper->{container_engine});

	$docker_helper->stop_containers();
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

    upstream u {
        zone z 1m;
    }

    server {
        listen %%PORT_8080%%;
        server_name localhost;

        location /api/ {
            api /;
        }

        location /pass {
            proxy_pass http://u;
        }
    }
}

EOF

}

sub check_peers {
	my ($docker_helper) = @_;

	my @ips = $docker_helper->get_container_ips();

	my $url = '/api/status/http/upstreams/u/peers';
	my $peers = get_json($url);

	my $container_engine = $docker_helper->{container_engine};

	for my $ip (@ips) {
		my $peer = "$ip:80";

		for (1 .. 120) {
			last if exists $peers->{$peer};

			$peers = get_json($url);
			select undef, undef, undef, 0.5;
		}

		is($peers->{$peer}{server}, $peer,
			"$container_engine peer '$peer' created");
	}
}

sub check_log {
	my ($t, $container_engine) = @_;

	is($t->find_in_file('angie_docker.log', 'Docker sends too large'), 0,
		"good buffer size for $container_engine containers");

	is($t->find_in_file('angie_docker.log', qr/\[error\]/), 0,
		"$container_engine: no errors in log");
}

###############################################################################
