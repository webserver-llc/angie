#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for "docker_max_object_size" directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;

require '../tests/docker_max_object_size.t';

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http upstream_zone docker proxy/);

my $docker_helper = eval {
	Test::Docker->new({container_engine => 'podman'});
};
if ($@) {
	plan(skip_all => $@);
}

$t->plan(4);

test($t, $docker_helper);

###############################################################################
