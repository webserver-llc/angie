#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for Docker networks.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;

require '../tests/docker_networks.t';

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http http_api upstream_zone docker proxy/);

my $docker_helper_multi = eval {
	Test::Docker->new({
		container_engine => 'podman',
		networks => ['angie_net1', 'angie_net2', 'angie_net3']
	});
};
if ($@) {
	plan(skip_all => $@);
}

my $docker_helper_single = eval {
	Test::Docker->new({
		container_engine => 'podman',
		networks => ['angie_single_net']
	});
};
if ($@) {
	plan(skip_all => $@);
}

$t->write_file_expand('nginx.conf', prepare_config($docker_helper_multi));

my %test_cases = prepare_test_cases(
	$docker_helper_multi, $docker_helper_single);

$t->plan(scalar keys %test_cases);

$t->run();

$t->run_tests(\%test_cases);

###############################################################################
