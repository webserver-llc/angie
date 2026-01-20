package Test::Docker;

# (C) 2025 Web Server LLC

# Helper for nginx Docker tests.

###############################################################################

use warnings;
use strict;

use File::Basename;
use Test::More;

sub new {
	my $class  = shift;
	my $params = shift // {};

	my $container_engine = $params->{container_engine} // 'docker';

	die 'Incorrect container engine'
		unless $container_engine =~ /^(?:docker|podman)$/;

	unless (`which $container_engine 2>/dev/null`) {
		die "no $container_engine";
	}

	my $self = bless {
		network  => 'angie_test_net_' . basename($0, qw(.t)),
		registry => $ENV{TEST_ANGIE_DOCKER_REGISTRY} // 'docker.io',
	}, $class;

	$self->_init_endpoint($container_engine)
		or return;

	$self->{container_engine} = $container_engine;

	$self->_test_network()
		or return;

	return $self;
}

sub _init_endpoint {
	my ($self, $container_engine) = @_;

	my $error = `$container_engine version 2>&1 1>/dev/null`;
	my $exit_code = $?;
	unless (($exit_code >> 8) == 0) {
		die "incorrect $container_engine setup: $error";
	}

	if ($container_engine eq 'docker') {
		$self->{endpoint} = '/var/run/docker.sock';

		unless (-e $self->{endpoint}) {
			die 'incorrect endpoint setup: ' . $self->{endpoint}
				. ' is missing';
		}

	} else {
		# this is the preferrable endpoint
		$self->{endpoint} = '/tmp/podman.sock';

		if (-e $self->{endpoint}) {
			# all is good, do nothing

		} elsif (defined $ENV{XDG_RUNTIME_DIR}
			&& -e $ENV{XDG_RUNTIME_DIR} . '/podman/podman.sock') {

			# this is the default endpoint on most systems
			$self->{endpoint} = $ENV{XDG_RUNTIME_DIR} . '/podman/podman.sock';
		} else {
			die 'incorrect podman setup: none of the known endpoints exists';
		}
	}

	unless (-w $self->{endpoint}) {
		die 'incorrect endpoint setup: ' . $self->{endpoint}
			. ' is not writable';
	}

	return 1;
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
