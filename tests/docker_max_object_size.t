#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for "docker_max_object_size" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, will stop all currently active containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $endpoint = "";
my $container_engine = "";

if (system('docker version 1>/dev/null 2>1') == 0) {
	$endpoint = '/var/run/docker.sock';
	$container_engine = 'docker';

# TODO
#} elsif (system('podman version 1>/dev/null 2>1') == 0) {
#	$endpoint = '/tmp/podman.sock';
#	$container_engine = 'podman';

} else {
	plan(skip_all => 'no Docker');
}

system("$container_engine network create test_net 1>/dev/null 2>1");
system("$container_engine network inspect test_net 1>/dev/null 2>1") == 0
	or die "can't create $container_engine network";

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker upstream_sticky proxy/)
	->plan(3);

###############################################################################

start_containers($t, 5);

restart_with_size($t, '4k');
check_log_error($t);

restart_with_size($t, '7k');
check_log_error($t);

restart_with_size($t, '16k');
check_log_ok($t);

stop_containers();

###############################################################################

sub lines {
	my ($t, $file, $pattern) = @_;

	my $path = $t->testdir() . '/' . $file;
	open my $fh, '<', $path or return "$!";
	my $value = map { $_ =~ /\Q$pattern\E/ } (<$fh>);
	close $fh;
	return $value;
}

sub check_log_ok {
	my ($t) = @_;

	for (1 .. 50) {
		last if lines($t, 'angie_docker.log', 'Docker peer');
		select undef, undef, undef, 0.5;
	}

	is(lines($t, 'angie_docker.log', '[error]'), 0,
		'good size of Docker object');
}

sub check_log_error {
	my ($t) = @_;

	my $found = 0;

	for (1 .. 50) {
		$found = lines($t, 'angie_docker.log', 'Docker sends too large');
		last if $found;
		select undef, undef, undef, 0.5;
	}

	ok($found, 'too large Docker object');
}

sub restart_with_size {
	my ($t, $size) = @_;

	my $tdir = $t->testdir();

	$t->stop();

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
			  . ' --network test_net docker.io/traefik/whoami'
			  . ' 1>/dev/null') == 0
			  or die "cannot start containers";
	}
}

sub stop_containers {
	system("$container_engine stop \$($container_engine ps -a -q)"
		. ' 1>/dev/null 2>1') == 0
		 or die "cannot stop containers";

	system("$container_engine rm \$($container_engine ps -a -q)"
		. ' 1>/dev/null 2>1') == 0
		 or die "cannot remove containers";
}

###############################################################################
