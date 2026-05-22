#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for stream_metric module.

###############################################################################

use warnings;
use strict;

use Test::Deep qw/ eq_deeply num /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

my $inc = 0;

use constant {
	MODE_COUNT    => $inc++,
	MODE_MIN      => $inc++,
	MODE_MAX      => $inc++,
	MODE_LAST     => $inc++,
	MODE_GAUGE    => $inc++,
	MODE_AVG_MEAN => $inc++,
	MODE_AVG_EXP  => $inc++,
	MODE_HIST     => $inc++,
};

our @MODE_NAMES = ('count', 'min', 'max', 'last', 'gauge', 'average mean',
	'average exp', 'histogram');

use constant 'TOLERANCE' => 1e-6;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_metric/);

my $conf = <<'EOF'

%%TEST_GLOBALS%%

daemon off;

events {
}

worker_processes 4;

stream {
    %%TEST_GLOBALS_STREAM%%

    variables_hash_bucket_size 1024;

    map $proxy_protocol_tlv_0xe0 $key {
        default $proxy_protocol_tlv_0xe0;
    }

    map $proxy_protocol_tlv_0xe1 $value {
        default $proxy_protocol_tlv_0xe1;
    }
EOF
;

my @metrics;

for (0 .. int(rand 32) + 1) {
	push @metrics, metric_generate(\$conf);
}

my $default_port = 8080;
my $port = $default_port;

foreach my $metric (@metrics) {
	my $metric_name = $metric->{name};

	$conf .= <<"EOF"

    server {
        listen 127.0.0.1:%%PORT_$port%% proxy_protocol;
        set \$metric_$metric_name \$key=\$value;
        return \$metric_${metric_name}_value;
    }
EOF
;
	$port++;
}

$conf .= "\n}";

$t->write_file_expand('nginx.conf', $conf);

$t->run()->plan(scalar @metrics);

###############################################################################

$port = $default_port;

foreach my $metric ( @metrics ) {
	subtest $metric->{name} => sub {
		my $keys_cnt = int(rand 10) + 1;
		plan tests => $keys_cnt;

		for (1 .. $keys_cnt) {
			my $test_passed = 1;

			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. rand(255) + 1);

			for (0 .. int(rand 10) + 1) {
				my $value = sprintf('%.8f', rand 99999 - rand 99999);

				metric_calculate($metric, $key, $value);

				my $data = metric_send($port, $key, $value);

				$test_passed = metric_compare($metric, $key, $data)
					&& $test_passed;
			}
			ok($test_passed, "$_ passed");
		}

		$port++;
	};
}

###############################################################################

sub metric_generate {
	my ($conf_ref) = @_;

	my %root = (name => '', nodes => []);

	$root{name} .= sprintf("%x", rand 16) for (0 .. 32);

	$$conf_ref .= "\n    metric_complex_zone $root{name}:1m expire=off {";

	for (0 .. int(rand 5) + 1) {
		my $mode = int(rand scalar @MODE_NAMES);

		my %node = (
			name => '',
			mode => $mode,
			data => {},
		);

		$node{name} .= sprintf("%x", rand 16) for (0 .. 32);

		$$conf_ref .= "\n        $node{name}  $MODE_NAMES[$mode]";

		if ($mode == MODE_AVG_MEAN) {
			my $count = int(rand 10) + 1;
			my $window = (rand 1 > 0.5) ? 0 : int(rand 8);

			$$conf_ref .= " count=$count window=";
			$$conf_ref .= ($window == 0) ? 'off' : "$window" . "s";

			$node{args} = {
				count  => $count,
				window => $window
			};

		} elsif ($mode == MODE_AVG_EXP) {
			my $factor = int(rand 100);

			$$conf_ref .= " factor=$factor";

			$node{args} = $factor / 100;

		} elsif ($mode == MODE_HIST) {
			my @buckets;

			for (0 .. int(rand 32) + 1) {
				my $value = rand 99999;
				push @buckets, $value;
				$$conf_ref .= " $value";
			}

			$node{args} = \@buckets;
		}

		$$conf_ref .= ';';

		push @{ $root{nodes} }, \%node;
	}

	$$conf_ref .= "\n    }\n";

	return \%root;
}

sub metric_calculate {
	my ($root, $key, $value) = @_;

	if (length($key) == 255) {
		$key .= "...";
	}

	foreach my $node (@{ $root->{nodes} }) {

		my $data = $node->{data};

		if ($node->{mode} == MODE_COUNT) {

			$data->{$key} //= 0;
			$data->{$key}++;

			next;
		}

		if ($node->{mode} == MODE_MIN) {

			if ((not exists $data->{$key}) || ($data->{$key} > $value)) {
				$data->{$key} = $value;
			}

			next;
		}

		if ($node->{mode} == MODE_MAX) {

			if ((not exists $data->{$key}) || ($data->{$key} < $value)) {
				$data->{$key} = $value;
			}

			next;
		}

		if ($node->{mode} == MODE_LAST) {

			$data->{$key} = $value;

			next;
		}

		if ($node->{mode} == MODE_GAUGE) {

			if (not exists $data->{$key}) {
				$data->{$key} = $value;
			} else {
				$data->{$key} += $value;
			}

			next;
		}

		if ($node->{mode} == MODE_AVG_MEAN) {

			my $args_count = $node->{args}{count};

			if (not exists $data->{$key}) {
				my @cache = ([$value, time()]);

				for (0 .. $args_count - 1) {
					push @cache, [0, 0];
				}

				$data->{$key} = {
					current => 1,
					value   => $value,
					cache   => \@cache
				};

				next;
			}

			my $avg_ctx = $data->{$key};

			my $cache = $avg_ctx->{cache};
			my $index = $avg_ctx->{current} % $args_count;

			$cache->[$index] = [$value, time()];

			my ($sum, $count) = (0, 0);
			my $current_time = time() - $node->{args}{window};

			if ($node->{args}{window} != 0) {

				for (my $i = 0; $i < $args_count; $i++) {
					if ($current_time <= $cache->[$i][1]) {
						$sum += $cache->[$i][0];
						$count++;
					}
				}

			} else {
				$index = $args_count - 1;

				if ($index > $avg_ctx->{current}) {
					$index = $avg_ctx->{current};
				}

				for (my $i = 0; $i <= $index; $i++) {
					$sum += $cache->[$i][0];
					$count++;
				}
			}

			$avg_ctx->{value} = $count ? $sum / $count : 0;
			$avg_ctx->{current}++;

			next;
		}

		if ($node->{mode} == MODE_AVG_EXP) {

			if (not exists $data->{$key}) {
				$data->{$key} = $value;
			} else {
				$data->{$key} += $node->{args} * ($value - $data->{$key});
			}

			next;
		}

		if ($node->{mode} == MODE_HIST) {

			my @buckets = @{ $node->{args} };

			if (not exists $data->{$key}) {
				my @result;

				foreach my $bucket (@buckets) {
					push @result, ($bucket >= $value) ? 1 : 0;
				}

				$data->{$key} = \@result;

				next;
			}

			foreach my $i (0 .. $#buckets) {
				if ($buckets[$i] >= $value) {
					${ $data->{$key} }[$i]++;
				}
			}
		}
	}
}

sub metric_send {
	my ($port, $key, $value) = @_;

	my $pp2_sig = pack("N3", 0x0D0A0D0A, 0x000D0A51, 0x5549540A);
	my $ver_cmd = pack('C', 0x21);
	my $family = pack('C', 0x11);

	my $packet = $pp2_sig . $ver_cmd . $family;

	my $ip1 = pack('N', 0x00000000);
	my $ip2 = pack('N', 0x00000000);
	my $ports = pack('nn', $port, $port);

	my $addrs = $ip1 . $ip2 . $ports;

	my $tlv = pack("CnA*", 0xe0, length($key), $key);
	$tlv .= pack("CnA*", 0xe1, length($value), $value);

	my $len = length($addrs) + length($tlv);

	$packet .= pack('n', $len) . $addrs . $tlv;

	stream('127.0.0.1:' . port($port))->io($packet);
}

sub metric_compare {
	my ($root, $key, $data) = @_;

	if (length($key) == 255) {
		$key .= "...";
	}

	my @data_values = split(", ", $data);

	foreach my $node (@{ $root->{nodes} }) {

		my $name = $node->{name};
		my $mode = $node->{mode};

		my $value_expected = $node->{data}{$key};
		my $value_got = shift @data_values;

		if ($mode == MODE_HIST) {
			my %expected;
			my $values_string = join(' ', @{$value_expected});

			my $ok = $values_string eq $value_got;
			unless ($ok) {
				diag("failed to compare metrics $name:");
				diag(explain({got => $value_got, expected => \%expected}));
				return 0;
			}

			next;
		}

		my $expected = ($mode == MODE_AVG_MEAN)
			? $value_expected->{value}
			: $value_expected;

		my $ok = eq_deeply($value_got, num($expected, TOLERANCE));
		unless ($ok) {
			diag("failed to compare metrics ($value_got != $expected)");
			return 0;
		}
	}

	return 1;
}
