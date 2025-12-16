package Test::Docker;

# (C) 2025 Web Server LLC

# Helper for nginx Docker tests.

###############################################################################

use warnings;
use strict;

use File::Basename;
use Test::More;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

sub new {
	my $class = shift;

	my $self = bless {
		network  => 'angie_test_net_' . basename($0, qw(.t)),
		registry => $ENV{TEST_ANGIE_DOCKER_REGISTRY} // 'docker.io',
	}, $class;

	if (system('docker version 1>/dev/null 2>&1') == 0) {
		$self->{endpoint} = '/var/run/docker.sock';
		$self->{container_engine} = 'docker';

	} elsif (system('podman version 1>/dev/null 2>&1') == 0) {
		$self->{endpoint} = '/tmp/podman.sock';
		unless (-e $self->{endpoint}) {
			die 'incorrect podman setup: ' . $self->{endpoint} . ' is missing';
		}
		unless (-w $self->{endpoint}) {
			die 'incorrect podman setup: ' . $self->{endpoint}
				. ' is not writable';
		}

		$self->{container_engine} = 'podman';

	} else {
		plan(skip_all => 'no Docker or Podman');
	}

	$self->_test_network();

	return $self;
}

sub _test_network {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};
	my $network = $self->{network};

	my $cmd = "$container_engine network create $network";
	note("create $container_engine network:\n$cmd");

	system($cmd . ' 1>/dev/null') == 0
		or die "can't create $container_engine network";

	$cmd = "$container_engine network inspect $network";
	note("inspect $container_engine network:\n$cmd");

	system($cmd . ' 1>/dev/null') == 0
		or die "can't inspect $container_engine network";

	return 1;
}

sub start_containers {
	my ($self, $count, $labels) = @_;

	my $container_engine = $self->{container_engine};
	my $network = $self->{network};
	my $registry = $self->{registry};

	$labels = "-l 'angie.network=$network' " . $labels;

	for my $idx (1 .. $count) {
		my $cmd = "$container_engine run -d $labels --name whoami-$idx"
			. " --network $network $registry/traefik/whoami";
		note("start $container_engine container $idx of $count");

		system($cmd . ' 1>/dev/null') == 0
			or die "cannot start $container_engine containers";
	}
}

sub stop_containers {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};
	my $network = $self->{network};

	my $list_containers_cmd = $container_engine
		. " ps -a -q --filter 'network=$network'";

	if (`$list_containers_cmd` eq '') {
		return;
	}

	my $cmd = "$container_engine stop \$($list_containers_cmd)";
	note("stop $container_engine containers:\n$cmd");

	if (system($cmd . ' 1>/dev/null') != 0) {
		$cmd = "$container_engine kill \$($list_containers_cmd)";
		note("force stop $container_engine containers:\n$cmd");

		system($cmd . ' 1>/dev/null') == 0
			or die "cannot stop $container_engine containers";
	}

	$cmd = "$container_engine rm -f \$($list_containers_cmd)";
	note("remove $container_engine containers:\n$cmd");

	system($cmd . ' 1>/dev/null') == 0
		or die "cannot remove $container_engine containers";
}

sub pause_containers {
	my ($self, $cmd) = @_;

	my $container_engine = $self->{container_engine};
	my $network = $self->{network};

	my $pause_cmd = "$container_engine $cmd "
		. "\$($container_engine ps -a -q --filter 'network=$network')";
	note("$container_engine $cmd:\n$pause_cmd");

	my $pause_cmd_res = system($pause_cmd . ' 1>/dev/null');

	note(`$container_engine ps -a`);

	die "cannot $cmd $container_engine containers"
		unless $pause_cmd_res == 0;
}

sub get_container_ips {
	my $self = shift;

	my $container_engine = $self->{container_engine};
	my $network = $self->{network};

	my $cmd = "$container_engine inspect "
		. "\$($container_engine ps -a -q --filter 'network=$network') "
		. "--format '{{.NetworkSettings.Networks.$network.IPAddress}}'";
	note("get $container_engine container ips:\n$cmd");

	my $data = `$cmd`;

	return split("\n", $data);
}

sub DESTROY {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};

	return unless defined $container_engine;

	$self->stop_containers();

	my $cmd = "$container_engine network rm $self->{network}";
	note("remove $container_engine network:\n$cmd");

	`$cmd 1>/dev/null`;
}

1;
