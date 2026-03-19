package Test::Docker;

# (C) 2025 Web Server LLC

# Helper for nginx Docker tests.

###############################################################################

use warnings;
use strict;

use File::Basename;
use IO::Socket::INET;
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

	my $error = `$container_engine -v 2>&1 1>/dev/null`;
	my $exit_code = $?;
	unless (($exit_code >> 8) == 0) {
		die "incorrect $container_engine setup: $error";
	}

	my $networks = $params->{networks}
		// ['angie_test_net_' . basename($0, qw(.t))];

	my $self = bless {
		_initialized     => 0,
		container_engine => $container_engine,
		networks         => $networks,
		registry         => $ENV{TEST_ANGIE_DOCKER_REGISTRY} // 'docker.io',
	}, $class;

	$self->_init_endpoint($params);
	$self->_test_endpoint();

	# enable cleanup in DESTROY before _test_network
	$self->{_initialized} = 1;

	$self->_test_network();

	# basic container check
	note("basic $container_engine container check ...");
	$self->start_containers(1, '');
	$self->stop_containers();
	note("basic $container_engine container check: passed");

	return $self;
}

sub _init_endpoint {
	my ($self, $params) = @_;

	if (defined $params->{endpoint}) {
		$self->{endpoint} = $params->{endpoint};
		return 1;
	}

	if ($self->{container_engine} eq 'docker') {
		$self->{endpoint} = 'unix:/var/run/docker.sock';
		return 1;
	}

	my @socket_locations = (
		'/tmp/podman.sock', # this is the preferrable endpoint for podman
		'/run/podman/podman.sock' # rootful podman socket location
	);
	# this is the default endpoint on most systems
	push @socket_locations, $ENV{XDG_RUNTIME_DIR} . '/podman/podman.sock'
		if defined $ENV{XDG_RUNTIME_DIR};

	foreach my $socket (@socket_locations) {
		note("checking podman socket $socket...");

		if (-e $socket) {
			if (-w $socket) {
				$self->{endpoint} = "unix:$socket";
				note("socket $socket: exists and writable");
				last;
			} else {
				note("socket $socket: exists but not writable, skipping");
			}
		} else {
			note("socket $socket: not found");
		}
	}

	die 'incorrect podman setup: none of the known endpoints exists'
		unless defined $self->{endpoint};

	return 1;
}

sub _test_endpoint {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};

	if ($self->{endpoint} =~ /^unix:(.+)$/) {
		my $socket = $1;
		unless (-e $socket) {
			die "incorrect $container_engine setup: $socket is missing";
		}
		unless (-w $socket) {
			die "incorrect $container_engine setup: $socket"
				. ' is not writable';
		}
	} elsif ($self->{endpoint} =~ /^http:\/\/(.+)$/) {
		my $host = $1;

		# try to connect to socket
		my $s = IO::Socket::INET->new(
			Proto    => 'tcp',
			PeerAddr => $host,
			Timeout  => 5,
		)
			or die "http endpoint for $container_engine API is not configured";

		my $request = <<"EOF";
GET /version HTTP/1.0
Host: $host

EOF

		$s->send($request) or die "send failed: $!\n";

		my $buffer;
		$s->recv($buffer, 1024) or die "recv failed: $!\n";

		$s->close();

		die "http endpoint for $container_engine API is not configured"
			unless $buffer && $buffer =~ /$container_engine/i;

	} elsif ($self->{endpoint} =~ /^https:/) {
		die 'https endpoints are not yet working';
	} else {
		die 'incorrect endpoint';
	}

	return 1;
}

sub _test_network {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};

	foreach my $network (@{ $self->{networks} }) {
		my $cmd = "$container_engine network create $network";
		note("create $container_engine network:\n$cmd");

		system($cmd . ' 1>/dev/null') == 0
			or die "can't create $container_engine network";

		$cmd = "$container_engine network inspect $network";
		note("inspect $container_engine network:\n$cmd");

		system($cmd . ' 1>/dev/null') == 0
			or die "can't inspect $container_engine network";
	}

	return 1;
}

sub start_containers {
	my ($self, $count, $labels) = @_;

	my $container_engine = $self->{container_engine};
	my $registry = $self->{registry};
	my @networks = @{ $self->{networks} };
	my $id = join('-', @networks);

	for my $idx (1 .. $count) {
		my $container = "whoami-$id-$idx";

		# With Podman, containers need to be in bridge mode in order to be
		# subsequently connected to various networks.
		my $cmd = "$container_engine create $labels --name $container"
			. " --network bridge $registry/traefik/whoami";
		note("create $container_engine container $container ($idx of $count)");

		system($cmd . ' 1>/dev/null') == 0
			or die "cannot create $container_engine container $container";

		foreach my $network (@networks) {
			$cmd = "$container_engine network connect $network $container";
			note("connect $container_engine container $container to $network");

			system($cmd . ' 1>/dev/null') == 0
				or die "cannot connect $container_engine container $container"
					. " to $network";
		}

		$cmd = "$container_engine start $container";
		note("start $container_engine container $container");

		system($cmd . ' 1>/dev/null') == 0
			or die "cannot start $container_engine container $container";
	}
}

sub stop_containers {
	my ($self) = @_;

	my $container_engine = $self->{container_engine};

	foreach my $network (@{ $self->{networks} }) {
		my $list_containers_cmd = $container_engine
			. " ps -a -q --filter 'network=$network'";

		if (`$list_containers_cmd` eq '') {
			return;
		}

		my $cmd = "$container_engine stop \$($list_containers_cmd)";
		note("stop $container_engine containers:\n$cmd");

		if (system($cmd . ' 1>/dev/null') != 0) {
			note("cannot stop containers, will try to force stop them");
			$cmd = "$container_engine kill \$($list_containers_cmd)";
			note("force stop $container_engine containers:\n$cmd");

			system($cmd . ' 1>/dev/null') == 0
				or diag("cannot stop $container_engine containers,"
					. 'will try to remove them');
		}

		$cmd = "$container_engine rm -f \$($list_containers_cmd)";
		note("remove $container_engine containers:\n$cmd");

		system($cmd . ' 1>/dev/null') == 0
			or die "cannot remove $container_engine containers";
	}
}

sub pause_containers {
	my ($self, $cmd) = @_;

	my $container_engine = $self->{container_engine};

	foreach my $network (@{ $self->{networks} }) {
		my $pause_cmd = "$container_engine $cmd "
			. "\$($container_engine ps -a -q --filter 'network=$network')";
		note("$container_engine $cmd:\n$pause_cmd");

		my $pause_cmd_res = system($pause_cmd . ' 1>/dev/null');

		note(`$container_engine ps -a`);

		die "cannot $cmd $container_engine containers"
			unless $pause_cmd_res == 0;
	}
}

sub get_container_ips_per_network {
	my ($self, $network) = @_;

	my $container_engine = $self->{container_engine};

	my $cmd = "$container_engine inspect "
		. "\$($container_engine ps -a -q --filter 'network=$network') "
		. "--format '{{.NetworkSettings.Networks.$network.IPAddress}}'";
	note("get $container_engine container ips:\n$cmd");

	my @ips = split("\n", `$cmd`);

	return @ips;
}

sub get_container_networks {
	my $self = shift;

	my %networks;

	foreach my $network (@{ $self->{networks} }) {
		my @ips = get_container_ips_per_network($self, $network);

		$networks{$network} = \@ips;
	}

	return %networks;
}

sub DESTROY {
	my ($self) = @_;

	return unless $self->{_initialized};

	$self->stop_containers();

	my $container_engine = $self->{container_engine};
	foreach my $network (@{ $self->{networks} }) {
		my $cmd = "$container_engine network rm $network";
		note("remove $container_engine network:\n$cmd");

		system("$cmd 1>/dev/null") == 0
			or diag("cannot remove $container_engine network $network!");
	}
}

1;
