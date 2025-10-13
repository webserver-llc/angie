package Test::Control;

# (C) 2025 Web Server LLC

###############################################################################

use warnings;
use strict;

use Exporter qw/import/;
our @EXPORT_OK = qw/upgrade terminate_pid check_master_processes_pids
	angie_ps show_angie_procs send_signal wait_for_reload stop_pid/;

use POSIX qw/ waitpid WNOHANG /;
use Test::Deep;
use Test::More;

use Test::Utils qw/trim/;

sub send_signal {
	my $sig = shift;

	my $pids = join(', ', @_);
	note("sending signal $sig from perl $$ to pids: $pids");
	kill $sig, @_;
}

sub upgrade {
	my ($t, $pid, $old_nworkers, $new_nworkers) = @_;

	ok($pid, "old master pid $pid file is not empty")
		or return;

	# ensure that all workers forked and renamed properly
	wait_for_active_workers($pid, $old_nworkers)
		or return;

	check_master_processes_pids($t, [$pid],
		"only old master process $pid is running")
		or return;

	# upgrade the executable on the fly
	send_signal('USR2', $pid);

	my $errors;
	my $found = 0;

	for (1 .. 150) {
		$errors = $t->tail_error_log();
		$found = grep { $_ =~ /, changing binary/ } @{ $errors };
		last if $found;
		select undef, undef, undef, 0.02;
	}

	ok($found, 'the first USR2 signal was received')
		or return;

	# second USR2 signal before handling the first one shouldn't cause issues
	send_signal('USR2', $pid);

	$found = 0;
	for (1 .. 150) {
		$found = grep { $_ =~ /: changing binary/ } @{ $errors };
		last if $found;
		select undef, undef, undef, 0.02;
		$errors = $t->tail_error_log();
	}

	ok($found, 'the first USR2 signal was handled')
		or return;

	# another USR2 signal during binary upgrade must be ignored
	send_signal('USR2', $pid);

	my $expected_error = "$pid#\\d+: the changing binary signal is ignored: "
		. "you should shutdown or terminate before either old or new "
		. "binary's process";

	$t->skip_errors_check('crit', $expected_error);

	# waiting for the error to appear in the log
	$found = 0;
	for (1 .. 150) {
		my $errors = $t->tail_error_log();
		$found = grep { $_ =~ /$expected_error/ } @{ $errors };
		last if $found;

		select undef, undef, undef, 0.02;
	}

	ok($found, 'the second USR2 signal was ignored');

	my $d = $t->testdir();

	# check old and new master processes' pids
	for (1 .. 150) {
		last if -e "$d/nginx.pid" && -e "$d/nginx.pid.oldbin";
		select undef, undef, undef, 0.2;
	}

	ok(-e "$d/nginx.pid.oldbin", 'old master pid file exists')
		or return;

	ok(-e "$d/nginx.pid", 'new master pid file exists')
		or return;

	my $new_pid = $t->get_master_pid();

	isnt($new_pid, $pid, "master pid changed from $pid to $new_pid")
		or return;

	# wait till workers are forked from new master
	wait_for_active_workers($new_pid, $new_nworkers // $old_nworkers)
		or return;

	# all workers are forked, we can safely check for masters

	check_master_processes_pids($t, [$pid, $new_pid],
		"an old $pid and a new $new_pid master processes are running")
		or return;

	return $new_pid;
}

sub terminate_pid {
	my ($pid, $signal) = @_;

	send_signal($signal, $pid);

	my $live;
	for (1 .. 150) {
		$live = pid_is_alive($pid);
		last if $live == 0;
		select undef, undef, undef, 0.2;
	}

	$live = master_is_alive($pid);
	is($live, 0, "master process $pid actually exited");
}

sub check_master_processes_pids {
	my ($t, $expected_processes, $tname) = @_;

	my $info = angie_ps();

	my $s = join(',', @{ $expected_processes });
	show_angie_procs($info, "checking master pids: [$s]");

	my (@master_processes, @pids);

	my $bin = File::Spec->canonpath($Test::Nginx::NGINX);
	my $prefix = File::Spec->canonpath($t->testdir());

	foreach my $master (@{ $info->{masters} }) {

		if (!(($master->{bin} eq $bin) && ($master->{prefix} eq $prefix))) {
			next;
		}
		push @master_processes, $master->{pid};
		push @pids, $master->{pid};
	}

	cmp_deeply(\@pids, bag(@{ $expected_processes }), $tname)
		or diag(explain({
			expected => $expected_processes,
			ps       => \@master_processes,
		}));
}

# return structured information about all angie processes running in system
sub angie_ps {
	my $binary = shift // 'angie:';

	my @all_procs = split "\n", `ps axwwo pid,ppid,command`;

	# consider everything that has '$binary' in 'command' to be related
	my @matches = grep { /$binary/ } @all_procs;

	my (@workers, @masters, @caches, @procs);

	foreach my $match (@matches) {
		my ($pid, $ppid, $cmd) = $match =~ /^\s*(\d+)\s+(\d+)\s+(.*+)$/;

		my %proc = (
			pid    => $pid,
			ppid   => $ppid,
			cmd    => $cmd,
		);

		# sort out process types and extract additional information
		if ($cmd =~ /worker process is shutting down/) {
			my ($generation) = $cmd =~ /#(\d+)$/;

			my %worker = (
				%proc,
				generation => $generation,
				state      => 'graceful_exit',
				orphan     => 1,
			);
			push @workers, \%worker;

		} elsif ($cmd =~ /worker process/) {
			my ($generation) = $cmd =~ /#(\d+)$/;

			my %worker = (
				%proc,
				generation => $generation,
				state      => 'active',
				orphan     => 1,
			);
			push @workers, \%worker;

		} elsif ($cmd =~ /master process/) {
			# TODO: single master (not used in tests though)

			my ($version, $build, $generation, $args)
				= $cmd =~ /master process v(.+) (\w+)?\s*#(\d+)\s+\[(.*)\]/;

			my ($bin, $prefix) = $args =~ /([^\s]+)\s+\-p\s+([^\s]+)\s+/;

			my %master = (
				%proc,
				build      => $build,
				version    => $version,
				generation => $generation,
				args       => $args,
				bin        => $bin // '',
				prefix     => File::Spec->canonpath($prefix) // '',

				workers    => [],
				caches     => [],
				procs      => [],
			);

			push @masters, \%master;

		} elsif ($cmd =~ /cache manager process/) {
			my %cache = (
				%proc,
				type   => 'manager',
				orphan => 1,
			);

			push @caches, \%cache;

		} elsif ($cmd =~ /cache loader process/) {
			my %cache = (
				%proc,
				type   => 'loader',
				orphan => 1,
			);
			push @caches, \%cache;

		} else {
			# nothing known matched, what left is probably zombies
			$proc{orphan} = 1;
			push @procs, \%proc;
		}
	}

	# assign all processes to corresponding masters
	foreach my $master (@masters) {
		foreach my $worker (@workers) {
			if ($worker->{ppid} == $master->{pid}) {
				$worker->{orphan} = 0;
				push @{ $master->{workers} }, $worker;
			}
		}

		foreach my $cache (@caches) {
			if ($cache->{ppid} == $master->{pid}) {
				$cache->{orphan} = 0;
				push @{ $master->{caches} }, $cache;
			}
		}

		foreach my $proc (@procs) {
			if ($proc->{ppid} == $master->{pid}) {
				$proc->{orphan} = 0;
				push @{ $master->{procs} }, $proc;
			}
		}
	}

	my @perl_children;
	foreach my $proc (@procs) {
		if ($proc->{ppid} eq $$) {
			$proc->{orphan} = 0;
			push @perl_children, $proc;
		}
	}

	# assign orphans to separate list
	my @orphans = grep { $_->{orphan} } (@workers, @caches, @procs);

	my %psinfo = (
		masters       => \@masters,
		workers       => \@workers,
		caches        => \@caches,
		orphans       => \@orphans,
		perl_children => \@perl_children,
	);

	return \%psinfo;
}

# display human-friendly angie processes for debug
sub show_angie_procs {
	my ($info, $msg) = @_;

	$msg //= '';

	note(">> angie processes state $msg");
	note("-- perl pid is $$");

	my $nperls = scalar @{ $info->{perl_children} };
	if ($nperls) {
		note("  -- perl descendants ($nperls) --\n");
	}
	foreach my $proc (@{ $info->{perl_children} }) {
		note("    " . $proc->{ppid} . '::' . $proc->{pid} . " "
			. $proc->{cmd} . "\n");
	}

	my $nmasters = scalar(@{ $info->{masters} });
	if ($nmasters) {
		note("-- masters ($nmasters) --\n");
	}

	foreach my $master (@{ $info->{masters} }) {
		note($master->{ppid} . '::' . $master->{pid}
			. ' master gen: ' . $master->{generation}
			. ' ver: ' . $master->{version}
			. ' prefix: ' . $master->{prefix} . "'\n");

		my $nworkers = scalar @{ $master->{workers} };
		if ($nworkers) {
			note("  -- workers ($nworkers) --\n");
		}
		foreach my $worker (@{ $master->{workers} }) {
			note('    ' . $worker->{ppid} . ':' . $worker->{pid}
				. ' worker gen: ' . $worker->{generation}
				. ' state: ' . $worker->{state} . "\n");
		}

		my $ncaches = scalar @{ $master->{caches} };
		if ($ncaches) {
			note("  -- caches ($ncaches) --\n");
		}
		foreach my $cache (@{ $master->{caches} }) {
			note('  ' . $cache->{ppid} . ':' . $cache->{pid}
				. ' cache ' . $cache->{type} . "\n");
		}

		my $nprocs = scalar @{ $master->{procs} };
		if ($nprocs) {
			note("  -- other procs ($nprocs) --\n");
		}
		foreach my $proc (@{ $master->{procs} }) {
			note('  ' . $proc->{ppid} . ':' . $proc->{pid}
				. ' proc ' . $proc->{cmd} . "\n");
		}
	}

	my $norphans = scalar(@{ $info->{orphans} });
	if ($norphans) {
		note("-- orphaned processes ($norphans) --\n");
	}
	foreach my $proc (@{ $info->{orphans} }) {
		note('    ' . $proc->{ppid} . '::' . $proc->{pid} . ' '
			. $proc->{cmd} . "\n");
	}

	note('<<');
}

sub active_worker_count {
	my ($master_pid) = @_;

	my $info = angie_ps();

	my $workers =
		scalar grep { $_->{ppid} eq $master_pid && $_->{state} eq 'active' }
		@{ $info->{workers} };

	return $workers;
}

# wait until new master has N active workers
sub wait_for_active_workers {
	my ($master_pid, $nworkers) = @_;

	my $wc;
	for (1 .. 150) {
		$wc = active_worker_count($master_pid);

		return 1 if $wc == $nworkers;
		select undef, undef, undef, 0.02;
	}

	diag("timed out waiting for workers: still only $wc of $nworkers workers");
	return 0;
}

sub worker_generation_count {
	my ($master_pid) = @_;

	my $info = angie_ps();

	my %generations;

	foreach my $worker (@{ $info->{workers} }) {
		if ($worker->{ppid} eq $master_pid && $worker->{state} eq 'active') {
			$generations{$worker->{generation}} = 1;
		}
	}

	return scalar keys %generations;
}

# TODO accept new_generation and check it
sub wait_for_reload {
	my ($master_pid) = @_;

	my $gc;
	for (1 .. 150) {
		$gc = worker_generation_count($master_pid);

		return if $gc == 1;
		select undef, undef, undef, 0.02;
	}

	diag("timed out waiting reload: still $gc different generations running");
}

sub pid_is_alive {
	my ($pid) = @_;
	my $out = `ps -p $pid -o pid=`;
	($out eq '') ? return 0 : return 1;
}

sub master_is_alive {
	my ($master_pid) = @_;

	my $info = angie_ps();

	foreach my $master (@{ $info->{masters} }) {
		if ($master->{pid} eq $master_pid) {
			return 1;
		}
	}

	return 0;
}

sub stop_pid {
	my ($pid, $force) = @_;

	my $exited;

	unless ($force) {

		# let's try graceful shutdown first
		kill 'QUIT', $pid;

		for (1 .. 900) {
			$exited = waitpid($pid, WNOHANG) != 0;
			last if $exited;
			select undef, undef, undef, 0.1;
		}
	}

	# then try fast shutdown
	if (!$exited) {
		kill 'TERM', $pid;

		for (1 .. 900) {
			$exited = waitpid($pid, WNOHANG) != 0;
			last if $exited;
			select undef, undef, undef, 0.1;
		}
	}

	# last try: brutal kill
	# this will kill the master process and all its worker processes
	if (!$exited) {
		kill '-KILL', getpgrp($pid);

		waitpid($pid, 0);
	}

	return 1;
}

1;
