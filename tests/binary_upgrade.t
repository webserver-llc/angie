#!/usr/bin/perl

# (C) 2024 Web Server LLC
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for binary upgrade - upgrading an executable file on the fly.

###############################################################################

use warnings;
use strict;
use feature 'state';

use Test::Most;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http unix/)->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       unix:%%TESTDIR%%/unix.sock;
        server_name  localhost;
    }
}

EOF

my $d = $t->testdir();

$t->run();

###############################################################################

my @checked_crit_errors;

subtest 'upgrade followed by termination of the old master process' => sub {
	my $pid = $t->read_file('nginx.pid');
	chomp($pid);

	# upgrade the executable on the fly
	upgrade_test($t, $pid)
		or return;

	# terminate old master process
	kill 'QUIT', $pid;

	for (1 .. 150) {
		last if ! -e "$d/nginx.pid.oldbin";
		select undef, undef, undef, 0.2;
	}

	ok(!-e "$d/nginx.pid.oldbin", 'old master pid deleted');
	ok(-e "$d/nginx.pid", 'new pid exists');

	isnt($t->read_file('nginx.pid'), $pid, 'master pid changed');

	ok(-e "$d/unix.sock", 'unix socket exists on old master shutdown');
};

my $is_previous_subtest_failed = !(Test::More->builder->summary)[-1];
subtest 'upgrade followed by termination of the new master process' => sub {

	# it may be dangerous to continue if previous subtest failed
	return
		if $is_previous_subtest_failed;

	my $pid = $t->read_file('nginx.pid');
	chomp($pid);

	# upgrade the executable on the fly
	upgrade_test($t, $pid)
		or return;

	$pid = $t->read_file('nginx.pid');
	chomp($pid);

	# terminate new master process
	kill 'TERM', $pid;

	for (1 .. 150) {
		last if ! -e "$d/nginx.pid.oldbin";
		select undef, undef, undef, 0.2
	}

	ok(!-e "$d/nginx.pid.oldbin", 'renamed pid deleted');
	ok(-e "$d/nginx.pid", 'new pid exists');

	isnt($t->read_file('nginx.pid'), $pid, 'master pid changed');

	ok(-e "$d/unix.sock", 'unix socket exists on new master termination');
};

$t->skip_errors_check('crit', @checked_crit_errors);

###############################################################################

sub upgrade_test {
	my ($t, $pid) = @_;

	ok($pid, 'master pid file is not empty')
		or return;

	# upgrade the executable on the fly
	kill 'USR2', $pid;

	# try to send second USR2 signal on master pid
	second_USR2_signal_test($t, $pid)
		or return;

	my $d = $t->testdir();

	for (1 .. 150) {
		last if -e "$d/nginx.pid" && -e "$d/nginx.pid.oldbin";
		select undef, undef, undef, 0.2;
	}

	ok(-e "$d/nginx.pid.oldbin", 'old master pid exists')
		or return;
	ok(-e "$d/nginx.pid", 'new master pid exists')
		or return;

	isnt($t->read_file('nginx.pid'), $pid, 'master pid changed')
		or return;
}

sub second_USR2_signal_test {
	my ($t, $pid) = @_;

	# second USR2 signal on master pid should be ignored and an error logged
	my $found = 0;
	for (1 .. 150) {
		my $errors = read_error_log($t);
		$found = grep { $_ =~ /changing binary/ } @{ $errors };
		last if $found;
		select undef, undef, undef, 0.02;
	}

	ok($found, 'the first USR2 signal was received')
		or return;

	kill 'USR2', $pid;

	my $expected_error = "$pid#\\d+: the changing binary signal is ignored: "
		. "you should shutdown or terminate before either old or new "
		. "binary's process";

	push @checked_crit_errors, $expected_error;

	# waiting for the error to appear in the log
	$found = 0;
	for (1 .. 150) {
		my $errors = read_error_log($t);
		$found = grep { $_ =~ /$expected_error/ } @{ $errors };
		last if $found;

		select undef, undef, undef, 0.02;
	}

	ok($found, 'the second USR2 signal was ignored');
}

# reads only new lines from error.log file
sub read_error_log {
	my $t = shift;

	state $error_log_fh;

	my $test_dir = $t->testdir();

	unless (defined $error_log_fh) {
		open($error_log_fh, '<', $test_dir . '/error.log')
			or die "Can't open $test_dir/error.log: $!";
	}

	seek($error_log_fh, 0, 1);

	my @error_log;
	for my $line (<$error_log_fh>) {
		chomp $line;
		next if $line =~ /\[debug\]/;
		push @error_log, $line;
	}

	return \@error_log;
}

1;
