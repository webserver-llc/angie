#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for containers count for the default buffer.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Docker;
use Test::Nginx;

require '../tests/docker_containers_count.t';

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'unsafe, may interfere with running containers.')
	unless $ENV{TEST_ANGIE_UNSAFE};

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker proxy/);

my $docker_helper = eval {
	Test::Docker->new({container_engine => 'podman'});
};
if ($@) {
	plan(skip_all => $@);
}

$t->plan(27)
	->write_file_expand('nginx.conf', prepare_config($docker_helper));

###############################################################################

test($t, $docker_helper);

###############################################################################
