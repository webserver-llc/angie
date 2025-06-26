#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for updating http upstreams via Docker labels.

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

system('docker version 1>/dev/null 2>1') == 0
	or plan(skip_all => 'no Docker');

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker/)->plan(756)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint unix:/var/run/docker.sock;

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

$t->run();

###############################################################################

system("docker network create test_net 1>/dev/null 2>1");
system("docker network inspect test_net 1>/dev/null 2>1") == 0
	or die "can't create Docker network";

test_containers($t, 3);
test_containers($t, 10);
test_containers($t, 1);
test_containers($t, 15);
test_containers($t, 4);
test_containers($t, 30);

###############################################################################

sub get_containers_ip {
	my ($t) = @_;

	my $tdir = $t->testdir();
	my $ip_file = 'containers_ip.txt';

	system(
		'docker ps --format "{{.ID}}" | while read -r line ; do '
			. 'echo $(docker inspect --format '
			. '"{{ .NetworkSettings.Networks.test_net.IPAddress }}" $line)'
			. ">> $tdir/$ip_file; "
		. 'done') == 0
		or die "cannot get container's IP";

	my $data = $t->read_file($ip_file);

	unlink("$tdir/$ip_file");

	return split("\n", $data);
}

sub start_containers {
	my ($t, $count) = @_;

	my $labels = '-l "angie.network=test_net"'
		 . ' -l "angie.http.upstreams.u1.port=80"'
		 . ' -l "angie.http.upstreams.u1.weight=2"'
		 . ' -l "angie.http.upstreams.u1.max_conns=20"'
		 . ' -l "angie.http.upstreams.u1.max_fails=5"'
		 . ' -l "angie.http.upstreams.u1.fail_timeout=10s"'
		 . ' -l "angie.http.upstreams.u1.backup=false"'

		 . ' -l "angie.http.upstreams.u2.port=90"'
		 . ' -l "angie.http.upstreams.u2.weight=5"'
		 . ' -l "angie.http.upstreams.u2.max_conns=25"'
		 . ' -l "angie.http.upstreams.u2.max_fails=10"'
		 . ' -l "angie.http.upstreams.u2.fail_timeout=5s"'
		 . ' -l "angie.http.upstreams.u2.backup=true"'

		 . ' -l "angie.stream.upstreams.u1.port=81"'
		 . ' -l "angie.stream.upstreams.u1.weight=10"'
		 . ' -l "angie.stream.upstreams.u1.max_conns=20"'
		 . ' -l "angie.stream.upstreams.u1.max_fails=5"'
		 . ' -l "angie.stream.upstreams.u1.fail_timeout=15s"'
		 . ' -l "angie.stream.upstreams.u1.backup=false"'

		 . ' -l "angie.stream.upstreams.u2.port=91"'
		 . ' -l "angie.stream.upstreams.u2.weight=15"'
		 . ' -l "angie.stream.upstreams.u2.max_conns=25"'
		 . ' -l "angie.stream.upstreams.u2.max_fails=1"'
		 . ' -l "angie.stream.upstreams.u2.fail_timeout=3s"'
		 . ' -l "angie.stream.upstreams.u2.backup=true"';

	for (my $idx = 0; $idx < $count; $idx++) {
		 system("docker run -d $labels --name whoami-$idx"
			  . ' --network test_net docker.io/traefik/whoami'
			  . ' 1> /dev/null 2>/dev/null') == 0
			  or die "cannot start containers";
	}
}

sub stop_containers {
	system('docker stop $(docker ps -a -q) 1>/dev/null 2>1') == 0
		or die "cannot stop containers";

	system('docker rm $(docker ps -a -q) 1>/dev/null 2>1') == 0
		or die "cannot remove containers";
}

sub pause_containers {
	my ($pause) = @_;

	system('docker '.$pause.' $(docker ps -a -q) 1>/dev/null 2>1');
}

sub check_peers {
	my ($t, $type, $upstream, $port) = @_;

	my @ips = get_containers_ip($t);

	my $j = get_json("/api/status/$type/upstreams/$upstream/");

	for my $ip (@ips) {
		my $peer = "$ip:$port";

		if (!(exists $j->{peers}{$peer})) {
			for (1 .. 50) {
				$j = get_json("/api/status/$type/upstreams/$upstream/");
				last if exists $j->{peers}{$peer};
				select undef, undef, undef, 0.5;
			}
		}

		is($peer, $j->{peers}{$peer}{server}, "create $type peer '$peer'");
	}

	pause_containers('pause');

	for my $ip (@ips) {
		my $peer = "$ip:$port";

		if ($j->{peers}{$peer}{state} eq 'up') {
			for (1 .. 50) {
				$j = get_json("/api/status/$type/upstreams/$upstream/");
				last if $j->{peers}{$peer}{state} eq 'down';
				select undef, undef, undef, 0.5;
			}
		}

		is($j->{peers}{$peer}{state}, 'down', "$type peer '$peer' is down");
	}

	pause_containers('unpause');

	for my $ip (@ips) {
		my $peer = "$ip:$port";

		if ($j->{peers}{$peer}{state} eq 'down') {
			for (1 .. 50) {
				$j = get_json("/api/status/$type/upstreams/$upstream/");
				last if $j->{peers}{$peer}{state} eq 'up';
				select undef, undef, undef, 0.5;
			}
		}

		is($j->{peers}{$peer}{state}, 'up', "$type peer '$peer' is up");
	}
}

sub test_containers {
	my ($t, $count) = @_;

	start_containers($t, $count);

	check_peers($t, 'http', 'u1', 80);
	check_peers($t, 'http', 'u2', 90);

	check_peers($t, 'stream', 'u1', 81);
	check_peers($t, 'stream', 'u2', 91);

	stop_containers();
}

###############################################################################
