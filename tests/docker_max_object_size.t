#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for "docker_max_object_size" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http upstream_zone docker proxy/);

my $docker_helper = Test::Docker->new();

$t->plan(4);

###############################################################################

my $labels = ' -l "angie.http.upstreams.u.port=80"'
	. ' -l "angie.http.upstreams.u.weight=2"'
	. ' -l "angie.http.upstreams.u.max_conns=20"'
	. ' -l "angie.http.upstreams.u.max_fails=5"'
	. ' -l "angie.http.upstreams.u.slow_start=10s"'
	. ' -l "angie.http.upstreams.u.fail_timeout=10s"'
	. ' -l "angie.http.upstreams.u.backup=false"'
	. ' -l "angie.http.upstreams.u.sid=sid1"';

$docker_helper->start_containers(5, $labels);

restart_with_size($t, $docker_helper->{endpoint}, '4k');
check_log_error($t, $docker_helper->{container_engine});

restart_with_size($t, $docker_helper->{endpoint}, '7k');
check_log_error($t, $docker_helper->{container_engine});

restart_with_size($t, $docker_helper->{endpoint}, '16k');
check_log_ok($t, $docker_helper->{container_engine});

$docker_helper->stop_containers();

###############################################################################

sub check_log_ok {
	my ($t, $container_engine) = @_;

	isnt($t->find_in_file('angie_docker.log', qr/\QDocker peer\E/), 0,
		"$container_engine peer created");

	is($t->find_in_file('angie_docker.log', qr/\[error\]/), 0,
		"good size of $container_engine object");
}

sub check_log_error {
	my ($t, $container_engine) = @_;

	ok($t->find_in_file('angie_docker.log', 'Docker sends too large'),
		"too large $container_engine object");
}

sub restart_with_size {
	my ($t, $endpoint, $size) = @_;

	my $tdir = $t->testdir();

	unlink("$tdir/angie_docker.log");

	$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

error_log %%TESTDIR%%/angie_docker.log notice;

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint unix:$endpoint;
    docker_max_object_size $size;

    upstream u {
        zone z 1m;
    }

    server {
        listen %%PORT_8080%%;
        server_name localhost;

        location /pass {
            proxy_pass http://u;
        }
    }
}

EOF

	$t->run();
	$t->stop();
}

###############################################################################
