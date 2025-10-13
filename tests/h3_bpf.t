#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for HTTP/3 with quic_bpf

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::HTTP3 qw /http3_get http3_start http3_end http3_close/;
use Test::Control qw/upgrade check_master_processes_pids terminate_pid
	angie_ps show_angie_procs send_signal/;
use POSIX qw(uname);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'linux only test') if $^O ne 'linux';
plan(skip_all => 'must be root') if $> != 0;

plan(skip_all => 'too many ports used, may break others on fail')
	unless $ENV{TEST_ANGIE_UNSAFE};

# Generally, bpf is expected to work with kernels 5.7+
# in practice, following systems trigger the issue:
#  "quic bpf failed to update connections map (1: Operation not permitted)"
#
# Below is the list of systems with kernel version known to fail and work
#
# system       | broken kernel version | working kernel version
# -------------+-----------------------+-----------------------
# debian 11    | 5.10.0-35             | 6.1
# redos 7      | 5.15.178              | 6.1-148.1
# rosafresh 12 | 5.15.185, 5.16, 5.17  | 6.1.152
# ubuntu 22.04 | 5.15.0-156            | 5.19.0-50
# altlinuxce10 | 5.10.82, 5.10.244     | 6.1.153
# altlinuxsp8  | 5.10.29, 5.10.176     | -
#
# all systems except alt sp8 has option to upgrade to working kernel

my @uname = uname();
my ($major, $minor) = $uname[2] =~ /([0-9])\.([0-9]+)/;
plan(skip_all => "linux 5.19+, has: $major.$minor")
	if $major < 5 or ($major == 5 && $minor < 19);

my $t = Test::Nginx->new()
	->has(qw/http http_ssl http_v3 quic_bpf rewrite socket_ssl_alpn cryptx/)
	->has_daemon('openssl')->prepare_ssl();

# see https://trac.nginx.org/nginx/ticket/1831
plan(skip_all => "perl >= 5.32 required")
	if ($t->has_module('perl') && $] < 5.032000);

sub generate_config {
	my ($t, $nworkers) = @_;

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

events {
}

worker_processes $nworkers;

quic_bpf on;

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:%%PORT_8980_UDP%% quic reuseport;
        server_name  test.example.com;

        location / {
            return 200 \$pid;
        }
        location /api/ {
            api /;
        }
    }
}

EOF
}

use constant {
	START_WORKERS => 8,

	# local port used to make http/3 connections to different workers
	BASE_PORT => 9000,
	DPORT     => 8980	# http/3 server is listening at this port
};

generate_config($t, START_WORKERS);

$t->run()->plan(4);

###############################################################################

our $last_port = BASE_PORT;
our $passed = 0;

subtest 'reload test: 8 -> 8' => sub {
	my $worker_map = quic_reload($t, START_WORKERS, START_WORKERS);
	$passed = ok(defined $worker_map, 'reload ok');
};

subtest 'reload test: 8 -> 3' => sub {
	return unless $passed;

	my $worker_map = quic_reload($t, START_WORKERS, 3);
	$passed = ok(defined $worker_map, 'reload ok');
};

my $worker_map;
subtest 'reload test: 3 -> 4' => sub {
	return unless $passed;

	$worker_map = quic_reload($t, 3, 4);
	$passed = ok(defined $worker_map, 'reload ok');
};

# now perform binary upgrade
subtest 'upgrade test: 4 -> 6' => sub {
	return unless $passed;

	my $rc = quic_upgrade($t, 4, 6, $worker_map);
	$passed = ok(defined $rc, 'upgrade ok');
};

sub quic_reload {
	my ($t, $old_nworkers, $new_nworkers) = @_;

	note("======= RELOAD TEST: $old_nworkers -> $new_nworkers ========");

	# with reuseport enabled, packets are delivered to per-worker socket by hash
	my $tbl = get_worker_port_matches($old_nworkers);
	ok(defined $tbl, 'test preparation ok: workers mapped to ports')
		or return;

	my $xtra_tbl = get_worker_port_matches($old_nworkers);
	ok(defined $xtra_tbl, 'test preparation ok: workers mapped to extra ports')
		or return;

	# ensure we have consistently working mapping
	my $ok = check_port_mapping($old_nworkers, $tbl);
	ok($ok, 'test preparation ok: source port stickyness verified')
		or return;

	my $conns = catch_workers($old_nworkers, $tbl);
	ok(defined $conns, 'test preparation ok: long connections started')
		or return;

	note('reloading...');

	if ($new_nworkers != $old_nworkers) {
		$t->{_api_added} = 0;
		generate_config($t, $new_nworkers);
	}

	$t->reload('/api/status/angie/generation');
	note('reload done');
	show_angie_procs(angie_ps(), 'after reload');

	# we are ready to perform the tests:

	# new requests must go into new workers and we should get a new mapping
	my $tbl2 = get_worker_port_matches($new_nworkers);
	ok(defined $tbl2, "new worker mapping created for $new_nworkers workers")
		or return;

	# new mapping does not match old:
	foreach my $pid (keys %{ $tbl2 }) {
		ok(!exists $tbl->{$pid}, "new worker $pid is not in old mapping");
	}

	# explicitly check that ports mapped previously to old workers now
	# result in connections to new workers
	foreach my $xport (values %{ $xtra_tbl }) {
		my $pid = http3_get('test.example.com', DPORT, '127.0.0.1', $xport);
		if (defined $pid) {
			ok(exists $tbl2->{$pid},
				"old port $xport leads to new worker $pid");
		} else {
			fail('failed to create new h3 connection with old mapping');
			return;
		}
	}

	# we must be able to get response from old workers:
	while (my ($cpid, $pair) = each %{ $conns }) {
		my $pid = http3_end($pair->{sock}, $pair->{sid});
		is($pid, $cpid, "response from $cpid is ok");
		http3_close($pair->{sock});
	}

	# kill workers that are shutting down to make test faster
	terminate_exiting_workers($t->get_master_pid());

	return $tbl2;
}

sub quic_upgrade {
	my ($t, $old_nworkers, $new_nworkers, $worker_map) = @_;

	note("======= UPGRADE TEST: $old_nworkers -> $new_nworkers ========");

	# first, create some long connections to existing workers

	my $pre_upg_conns = catch_workers($new_nworkers, $worker_map);
	ok(defined $pre_upg_conns, 'test preparation ok: long connections started')
		or return;

	$t->{_api_added} = 0;
	generate_config($t, $new_nworkers);

	note('Upgrading binary...');

	my $mpid = $t->get_master_pid();

	my $new_mpid = upgrade($t, $mpid, $old_nworkers, $new_nworkers);
	ok(defined $new_mpid, 'upgrade performed')
		or return;

	note('Running with two masters...');

	# now we have 2 masters and 2 set of worker processes running....
	show_angie_procs(angie_ps(), 'in upgrade');

	# new requests should be delivered to both old and new workers
	my $tbl3 = get_worker_port_matches($old_nworkers + $new_nworkers);
	ok(defined $tbl3, 'mixed old/new workers mapping created');

	# terminate old master process
	send_signal('QUIT', $mpid);

	# and open connections in old workers are still alive;
	# get response and close them, so that old workers could exit quickly
	while (my ($cpid, $pair) = each %{ $pre_upg_conns }) {
		my $pid = http3_end($pair->{sock}, $pair->{sid});
		is($pid, $cpid, "response from $cpid is ok");
		http3_close($pair->{sock});
	}

	# kill workers that are shutting down to make test faster
	terminate_exiting_workers($mpid);

	is($t->get_master_pid(), $new_mpid,
		"new master pid $new_mpid persists after old master $mpid terminates");

	check_master_processes_pids($t, [$new_mpid],
		"only new master process $new_mpid is running");

	# now requests should be delivered to new workers only
	my $tbl4 = get_worker_port_matches($new_nworkers);
	ok(defined $tbl4, 'upgraded workers only mapping created');
}

# pick local port numbers that hash to specific workers
sub get_worker_port_matches {
	my ($nworkers) = @_;

	# number of local port increments in attempt to reach specific worker
	my $ntries = 256;

	# mapping of uniq workers to local ports
	# res[worker_pid] = local_port
	my %res;

	my $nfound = 0;

	for my $k (1 .. $ntries) {
		my $curr_port = $last_port + $k;
		my $pid = http3_get('test.example.com', DPORT, '127.0.0.1',
			$curr_port);

		if (!defined $pid) {
			note("failed to get h3 response using $curr_port "
				. "(off $k nwrk:$nworkers)");
			return;
		}

		if (!defined $res{$pid}) {
			$res{$pid} = $curr_port;
			note("found match: local port $curr_port <==> worker pid $pid");
			$nfound++;
		}

		if ($nfound == $nworkers)  {
			note("worker mapping complete in $k steps");
			$last_port = $curr_port + 1;
			return \%res;
		}
	}

	note("failed to collect worker mapping after $ntries attempts"
		. " base port:$last_port");

	# we failed to pick local ports
	return;
}

sub check_port_mapping {
	my ($nworkers, $tbl) = @_;

	# number of requests to perform to same worker
	my $ntries = 1;

	# attempt to run multiple requests using same source port may lead
	# to situation when client will receive packet from incorrect connection
	# (this looks like a client library issue: not checking for own DCID?)
	# my $ntries = 10;

	while(my ($xpid, $xport) = each %{ $tbl }) {
		for my $k (1 .. $ntries) {
			my $pid = http3_get('test.example.com', DPORT, '127.0.0.1', $xport);
			if (!defined $pid) {
				note('failed to get h3 response');
				return 0;
			}

			if ($pid != $xpid) {
				note("source port $xport do not stick to $xpid");
				return 0;
			}
		}
		note("verify worker pid $xpid: $ntries tries ok");
	}
	note('source port stickyness verified ok');
	return 1;
}

sub catch_workers {
	my ($nworkers, $tbl) = @_;

	# start http request to worker so it did not exit on reload
	my %open_conns;

	while (my ($xpid, $xport) = each %{ $tbl }) {
		my ($s, $sid) =
			http3_start('test.example.com',  DPORT, '127.0.0.1', $xport);
		if (!defined $s || !defined $sid) {
			return;
		}
		$open_conns{$xpid} = {sock => $s, sid => $sid};
		note("open long h3 conn to pid $xpid stream_id $sid");
	}

	return \%open_conns;
}

###############################################################################

sub terminate_exiting_workers {
	my ($master_pid) = @_;

	my $info = angie_ps();

	note('killing old workers');

	foreach my $worker (@{ $info->{workers} }) {
		if ($worker->{state} eq 'graceful_exit'
            && $worker->{ppid} eq $master_pid)
		{
			terminate_pid($worker->{pid}, 'SIGTERM');
		}
	}
}

1;
