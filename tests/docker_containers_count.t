#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for containers count for the default buffer.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, will stop all currently active containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $endpoint = '';
my $container_engine = '';

if (system('docker version 1>/dev/null 2>&1') == 0) {
	$endpoint = '/var/run/docker.sock';
	$container_engine = 'docker';

} elsif (system('podman version 1>/dev/null 2>&1') == 0) {
	$endpoint = '/tmp/podman.sock';
	$container_engine = 'podman';

} else {
	plan(skip_all => 'no Docker or Podman');
}

my $registry = $ENV{TEST_ANGIE_DOCKER_REGISTRY} // 'docker.io';

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker upstream_sticky proxy/)
	->plan(27);

system("$container_engine network create test_net 1>/dev/null 2>&1");
system("$container_engine network inspect test_net 1>/dev/null 2>&1") == 0
	or die "can't create $container_engine network";

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

error_log %%TESTDIR%%/angie_docker.log notice;

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint unix:$endpoint;

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

###############################################################################

stop_containers();

start_containers($t, 25);

$t->run();

check_peers($t);

$t->stop();

check_log($t);

stop_containers();

###############################################################################

sub get_container_ips {
	my ($t) = @_;

	my $tdir = $t->testdir();
	my $ip_file = 'containers_ip.txt';

	system(
		"$container_engine ps --format \"{{.ID}}\" | while read -r line ; do "
			. "echo \$($container_engine inspect --format "
			. '"{{ .NetworkSettings.Networks.test_net.IPAddress }}" $line)'
			. ">> $tdir/$ip_file; "
		. 'done') == 0
		or die "cannot get $container_engine container's IP";

	my $data = $t->read_file($ip_file);

	unlink("$tdir/$ip_file");

	return split("\n", $data);
}

sub check_peers {
	my ($t) = @_;

	my @ips = get_container_ips($t);

	my $url = '/api/status/http/upstreams/u/peers';
	my $peers = get_json($url);

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
	my ($t) = @_;

	is($t->find_in_file('angie_docker.log', 'Docker sends too large'), 0,
		"good buffer size for $container_engine containers");

	is($t->find_in_file('angie_docker.log', qr/\[error\]/), 0,
		"$container_engine: no errors in log");
}

sub start_containers {
	my ($t, $count) = @_;

	my $labels = '-l "angie.network=test_net"'
		. ' -l "angie.http.upstreams.u.port=80"'
		. ' -l "angie.http.upstreams.u.weight=2"'
		. ' -l "angie.http.upstreams.u.max_conns=20"'
		. ' -l "angie.http.upstreams.u.max_fails=5"'
		. ' -l "angie.http.upstreams.u.slow_start=10s"'
		. ' -l "angie.http.upstreams.u.fail_timeout=10s"'
		. ' -l "angie.http.upstreams.u.backup=false"'
		. ' -l "angie.http.upstreams.u.sid=sid1"';

	for (my $idx = 0; $idx < $count; $idx++) {
		system("$container_engine run -d $labels --name whoami-$idx"
			. " --network test_net $registry/traefik/whoami"
			. ' 1>/dev/null') == 0
			or die "cannot start $container_engine containers";
	}
}

sub stop_containers {
	if (`$container_engine ps -a -q` eq '') {
		return;
	}

	system("$container_engine stop \$($container_engine ps -a -q)"
		. ' 1>/dev/null 2>&1') == 0
		or die "cannot stop $container_engine containers";

	system("$container_engine rm \$($container_engine ps -a -q)"
		. ' 1>/dev/null 2>&1') == 0
		or die "cannot remove $container_engine containers";
}

###############################################################################
