#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for updating http upstreams via Podman labels.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;

require '../tests/docker.t';

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker upstream_sticky proxy/)
	->has(qw/stream stream_upstream_zone stream_upstream_sticky/);

my $docker_helper = eval {
	Test::Docker->new({container_engine => 'podman'});
};
if ($@) {
	plan(skip_all => $@);
}

$t->write_file_expand('nginx.conf', prepare_config($docker_helper));

my %test_cases = prepare_test_cases($docker_helper);

$t->plan(scalar keys %test_cases);

$t->run();

$t->run_tests(\%test_cases);

###############################################################################
