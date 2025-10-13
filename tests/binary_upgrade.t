#!/usr/bin/perl

# (C) 2024 Web Server LLC
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for binary upgrade - upgrading an executable file on the fly.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Control qw/upgrade terminate_pid check_master_processes_pids/;

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

subtest 'upgrade followed by termination of the old master process' => sub {
	my $pid = $t->get_master_pid();

	# upgrade the executable on the fly
	my $new_pid = upgrade($t, $pid, 1)
		or return;

	# terminate old master process
	terminate_pid($pid, 'QUIT');
	ok(!-e "$d/nginx.pid.oldbin", 'old master pid deleted');
	ok(-e "$d/nginx.pid", 'new pid exists');

	is($t->get_master_pid(), $new_pid,
		"new master pid $new_pid persists after old master $pid terminates");

	check_master_processes_pids($t, [$new_pid],
		"only new master process $new_pid is running");

	ok(-e "$d/unix.sock", 'unix socket exists on old master shutdown');
};

my $is_previous_subtest_failed = !(Test::More->builder->summary)[-1];
subtest 'upgrade followed by termination of the new master process' => sub {

	# it may be dangerous to continue if previous subtest failed
	return
		if $is_previous_subtest_failed;

	my $pid = $t->get_master_pid();

	# upgrade the executable on the fly
	my $new_pid = upgrade($t, $pid, 1)
		or return;

	# terminate new master process
	terminate_pid($new_pid, 'TERM');
	ok(!-e "$d/nginx.pid.oldbin", 'old master pid deleted');
	ok(-e "$d/nginx.pid", 'new pid exists');

	is($t->get_master_pid(), $pid,
		"master pid $pid equals old pid after new master $new_pid terminates");

	check_master_processes_pids($t, [$pid],
		"only old master process $pid is running");

	ok(-e "$d/unix.sock", 'unix socket exists on new master termination');
};

###############################################################################


1;
