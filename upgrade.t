#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for binary upgrade.

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

plan(skip_all => 'can leave orphaned process group')
	unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->plan(2)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

events {
}

EOF

$t->run();

###############################################################################

my $pid = $t->read_file('nginx.pid');
ok($pid, 'master pid');

kill 'USR2', $pid;

for (1 .. 10) {
	last if -e $t->testdir() . '/nginx.pid'
		&& -e $t->testdir() . '/nginx.pid.oldbin';
	select undef, undef, undef, 0.2
}

isnt($t->read_file('nginx.pid'), $pid, 'master pid changed');

kill 'QUIT', $pid;

###############################################################################
