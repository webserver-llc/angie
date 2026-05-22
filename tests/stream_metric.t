#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for stream_metric module.

###############################################################################

use warnings;
use strict;

use List::Util qw/ sum /;
use Test::More;
use Test::Deep qw/ cmp_deeply num ignore superhashof /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;
use Test::Utils qw/ get_json /;

###############################################################################

use constant 'TOLERANCE' => 1e-6;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_metric stream_return/);

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

    metric_zone reload_inline:128k count;

    metric_complex_zone reload_complex:128k {
        1 count;
        2 average mean count=5 window=off;
        3 histogram 1 2 3;
        # 4 gauge;
    }

    metric_zone counter:128k discard_key=angie count;

    metric_zone min:128k min;
    metric_zone max:128k max;
    metric_zone last:128k last;
    metric_zone gauge:128k gauge;

    metric_zone avg0:128k average mean;
    metric_zone avg1:128k average mean count=3;
    metric_zone avg2:128k average mean window=1s;

    metric_zone avg_exp1:128k average exp factor=80;
    metric_zone avg_exp2:128k average exp factor=20;

    metric_zone hist1:128k expire=on histogram 0.1 2 5 8 10 inf;
    metric_zone hist2:128k expire=off histogram inf 2 5 10 0.1 8;

    metric_zone var:128k count;
    metric_zone var2:128k last;
    metric_zone var3:128k last;

    metric_complex_zone complex_var:128k {
        count count;
        avg   average mean count=40;
        hist  histogram 1 2 3 10 11 12 13 14 15 16 17 18 19 20 21 22 23 34 90;
    }

    server {
        listen 127.0.0.1:%%PORT_8090%% proxy_protocol;
        set $metric_reload_inline  $key=$value;
        set $metric_reload_complex $key=$value;
        return "$metric_reload_inline;$metric_reload_complex";
    }

    server {
        listen 127.0.0.1:%%PORT_8091%% proxy_protocol;
        set $metric_var $key;
        return "$metric_var;$metric_var_key;$metric_var_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8092%% proxy_protocol;
        set $metric_var $key=$value;
        return "$metric_var;$metric_var_key;$metric_var_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8093%% proxy_protocol;
        set $metric_var_key   $key;
        set $metric_var_value $value;
        return "$metric_var;$metric_var_key;$metric_var_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8094%% proxy_protocol;
        set $metric_counter $key;
        return $metric_counter_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8095%% proxy_protocol;
        set $metric_min $key=$value;
        return $metric_min_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8096%% proxy_protocol;
        set $metric_max $key=$value;
        return $metric_max_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8097%% proxy_protocol;
        set $metric_last $key=$value;
        return $metric_last_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8098%% proxy_protocol;
        set $metric_gauge $key=$value;
        return $metric_gauge_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8099%% proxy_protocol;
        set $metric_avg0 avg1_base=$value;
        set $metric_avg1 count=$value;
        return "$metric_avg0_value;$metric_avg1_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8100%% proxy_protocol;
        set $metric_avg0 avg2_base=$value;
        set $metric_avg2 window=$value;
        return "$metric_avg0_value;$metric_avg2_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8101%% proxy_protocol;
        set $metric_avg_exp1 $key=$value;
        return $metric_avg_exp1_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8102%% proxy_protocol;
        set $metric_avg_exp2 $key=$value;
        return $metric_avg_exp2_value;
    }

    server {
        listen 127.0.0.1:%%PORT_8103%% proxy_protocol;
        set $metric_hist1 $key=$value;
        set $metric_hist2 $key=$value;
        return "$metric_hist1_value;$metric_hist2_value";
    }

    server {
        listen 127.0.0.1:%%PORT_8104%% proxy_protocol;
        set $metric_complex_var_key   $key;
        set $metric_complex_var_value $value;
        return "$metric_complex_var_value";
    }
EOF
;

if ($t->has_module('http_api')) {
	$conf .= <<'EOF'

    metric_zone stage1:128k last;
    metric_zone stage3:128k last;

    metric_complex_zone block0:128k {
        count count;
        min   min;
        max   max;
        last  last;
        hist  histogram 1 5 10;
        gauge gauge;
        avg   average mean;
    }

    metric_complex_zone block_large_slabs:128k {
        count count;
        min   min;
        hist  histogram 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21
                        22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39
                        40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57
                        58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75
                        76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93
                        94 95 96 97 98 99 100 101 102 103 104 105 106 107 108;
        max   max;
        hist2 histogram 1 2 3 4 5;
        avg   average mean count=100;
        last  last;
        gauge gauge;
    }

    metric_complex_zone block1:128k expire=on discard_key=expired {
        count count;
        min   min;
        max   max;
        avg1  average exp;
        avg2  average mean window=2s;
        last  last;
        avg3  average mean count=20;
        hist  histogram 1 500 1000 10000;
        gauge gauge;
    }

    metric_complex_zone block2:128k expire=on {
        count count;
        min   min;
        max   max;
        last  last;
        hist  histogram 1 5 10;
        gauge gauge;
        avg   average mean;
    }

    metric_complex_zone block3:128k expire=off {
        count count;
        min   min;
        max   max;
        last  last;
        gauge gauge;
        avg   average exp;
        hist  histogram 1 5 10;
    }

    metric_complex_zone block4:128k expire=off discard_key=some_key {
        count count;
        min   min;
        max   max;
        last  last;
        gauge gauge;
        avg   average mean;
        hist  histogram 1 5 10;
    }

    server {
        listen 127.0.0.1:%%PORT_8105%% proxy_protocol;
        metric stage1 $key=$bytes_sent on=connect;
        return "some_data";
    }

    server {
        listen 127.0.0.1:%%PORT_8106%% proxy_protocol;
        metric stage1 $key=$connection on=connect;
        return "some_data";
    }
EOF
;

	if ($t->has_module('stream_mqtt_preread')) {
		$conf .= <<'EOF'

    metric_zone stage2:128k last;

    server {
        listen 127.0.0.1:%%PORT_8107%%;
        mqtt_preread on;
        metric stage2 $mqtt_preread_clientid=1 on=preread;
        return "$mqtt_preread_clientid $metric_stage2";
    }
EOF
;
    }

	$conf .= <<'EOF'

    server {
        listen 127.0.0.1:%%PORT_8108%% proxy_protocol;
        metric stage3 $key=$bytes_sent on=end;
        return "some_data";
    }

    server {
        listen 127.0.0.1:%%PORT_8109%% proxy_protocol;
        metric block0 $key=$value on=connect;
    }

    server {
        listen 127.0.0.1:%%PORT_8110%% proxy_protocol;
        metric block_large_slabs $key=$value;
    }

    server {
        listen 127.0.0.1:%%PORT_8111%% proxy_protocol;
        metric block1 $key=$value;
    }

    server {
        listen 127.0.0.1:%%PORT_8112%% proxy_protocol;
        set $metric_block2 $key=$value;
    }

    server {
        listen 127.0.0.1:%%PORT_8113%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_count";
    }

    server {
        listen 127.0.0.1:%%PORT_8114%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_min";
    }

    server {
        listen 127.0.0.1:%%PORT_8115%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_max";
    }

    server {
        listen 127.0.0.1:%%PORT_8116%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_last";
    }

    server {
        listen 127.0.0.1:%%PORT_8117%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_hist";
    }

    server {
        listen 127.0.0.1:%%PORT_8118%% proxy_protocol;
        set $metric_block1_key $key;
        return "$metric_block1_value_gauge";
    }

    server {
        listen 127.0.0.1:%%PORT_8119%% proxy_protocol;
        set $metric_block3_key    $key;
        set $metric_block3_value  $value;
    }

    server {
        listen 127.0.0.1:%%PORT_8120%% proxy_protocol;
        metric block4 $key=$value on=preread;
        return "ok";
    }
}

http {
    server {
        listen 127.0.0.1:%%PORT_8080%%;

        location /api/ {
            allow 127.0.0.1;
            deny  all;

            location /api/status/ {
                api /status/;
            }

            api /status/stream/metric_zones/;
        }
    }
EOF
;
}

$conf .= "}";

$t->write_file_expand('nginx.conf', $conf);

$t->run();

###############################################################################

my %test_cases = (
	'api metric tree' => sub {
		plan(skip_all => 'no http api')
			unless $t->has_module('http_api');

		my $res = get_json('/api/status/');
		cmp_deeply(
			$res->{stream}{metric_zones},
			superhashof({}),
			'api metric tree'
		);
	},

	'reload' => sub {
		plan(skip_all => 'reload is not working (perl >= 5.32 required)')
			unless $t->has_feature('reload');

		ok($t->reload(), 'reload 1');

		metric_send(8090, 'angie', 1);
		metric_send(8090, 'angie', 2);

		ok($t->reload(), 'reload 2');

		my $new_conf = $t->read_file('nginx.conf');

		$new_conf =~ s/reload_inline:128k/reload_inline:256k/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload metric zone size 1');

		like(metric_send(8090, 'angie', 1), qr/angie=1;/,
			'reload metric zone size 2');

		$new_conf =~ s/reload_inline:256k count/reload_inline:256k gauge/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload metric mode 1');

		like(metric_send(8090, 'angie', 1), qr/angie=1;angie=4/,
			'reload metric mode');

		metric_send(8090, 'angie', 10);
		metric_send(8090, 'angie', 10);

		$new_conf =~ s/# 4 gauge/4 gauge/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload metrics count 1');

		like(metric_send(8090, 'angie', 1), qr/angie=22;angie=1/,
			'reload metric count 2');

		metric_send(8090, 'angie', 10);
		metric_send(8090, 'angie', 10);

		$new_conf =~ s/count=5/count=9/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload average mean count 1');

		like(metric_send(8090, 'angie', 1), qr/angie=43;angie=1/,
			'reload average mean count 2');

		metric_send(8090, 'angie', 10);
		metric_send(8090, 'angie', 10);

		$new_conf =~ s/window=off/window=99m/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload average mean window 1');

		like(metric_send(8090, 'angie', 1), qr/angie=64;angie=1/,
			'reload average mean window 2');

		metric_send(8090, 'angie', 10);
		metric_send(8090, 'angie', 10);

		$new_conf =~ s/3 histogram 1 2 3/3 histogram 1 2 3 4 5/;
		$t->write_file('nginx.conf', $new_conf);
		ok($t->reload(), 'reload histogram 1');

		like(metric_send(8090, 'angie', 1),
			qr/angie=85;angie=1, 1, 1 1 1 1 1, 1/,
			'reload histogram 2');

		ok($t->reload(), 'reload 3');

		SKIP: {

		skip "no --with-debug", 6 unless $t->has_module('debug');

		$t->stop();

		my $log = $t->read_file('error.log');

		like($log, qr/zone "\w+" uses the "\d+" size/, 'reload debug 1');
		like($log, qr/zone "\w+" uses the "\w+" mode/, 'reload debug 2');
		like($log, qr/zone "\w+" uses the "\d+" metrics/, 'reload debug 3');
		like($log, qr/zone "\w+" uses the "count=\d+"/, 'reload debug 4');
		like($log, qr/the "window=" parameter of metric/, 'reload debug 5');
		like($log, qr/uses the "\d+" buckets/, 'reload debug 6');

		$t->run();

		}
	},

	'key value' => sub {
		like(metric_send(8091, "key==1", 0),    qr/^key==1;key=;1$/m,
			'key value 1');
		like(metric_send(8091, "key==10", 0),   qr/^key==2;key=;2$/m,
			'key value 2');
		like(metric_send(8091, "k=e=y==1", 0),  qr/^k=e=y==1;k=e=y=;1$/m,
			'key value 3');
		like(metric_send(8091, "=k=e=y==1", 0), qr/^=k=e=y==1;=k=e=y=;1$/m,
			'key value 4');
		like(metric_send(8091, "==1", 0), qr/^==1;=;1$/m, 'key value 5');
		like(metric_send(8091, "=1", 0),  qr/^;;$/m, 'key value 6');
		like(metric_send(8091, "=", 0),   qr/^;;$/m, 'key value 7');
		like(metric_send(8091, "key", 0), qr/^key=1;key;1$/m, 'key value 8');
	},

	'variables' => sub {
		like(metric_send(8092, 'angie', "tt"), qr/^angie=1;angie;1$/m,
			'variables 1 - 1');
		like(metric_send(8092, 'angie', -1),   qr/^angie=2;angie;2$/m,
			'variables 1 - 2');
		like(metric_send(8092, 'angie', 0.01), qr/^angie=3;angie;3$/m,
			'variables 1 - 3');
		like(metric_send(8092, 'foo', 548),    qr/^foo=1;foo;1$/m,
			'variables 1 - 4');
		like(metric_send(8092, 'foo', 0),      qr/^foo=2;foo;2$/m,
			'variables 1 - 5');

		like(metric_send(8093, 'angie', "t0"), qr/^angie=4;angie;4$/m,
			'variables 2 - 1');
		like(metric_send(8093, 'angie', 65),   qr/^angie=5;angie;5$/m,
			'variables 2 - 1');
		like(metric_send(8093, 'angie', 0.1),  qr/^angie=6;angie;6$/m,
			'variables 2 - 1');
		like(metric_send(8093, 'foo', 7),      qr/^foo=3;foo;3$/m,
			'variables 2 - 1');
		like(metric_send(8093, 'foo', 0),      qr/^foo=4;foo;4$/m,
			'variables 2 - 1');
	},

	'mode counter' => sub {
		my $res;

		my $n = int(rand 10) + 1;

		for (0 .. $n) {
			$res = metric_send(8094, 'counter', 0);
		}

		is($res, $n + 1, 'mode counter');
	},

	'mode min' => sub {
		my $n = int(rand 10) + 1;

		my $res;
		my $min = 99999;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			if ($min > $v) {
				$min = $v;
			}

			$res = metric_send(8095, 'angie', $v);
		}

		is($res, $min, 'mode min');
	},

	'mode max' => sub {
		my $n = int(rand 10) + 1;

		my $res;
		my $max = -99999;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			if ($max < $v) {
				$max = $v;
			}

			$res = metric_send(8096, 'angie', $v);
		}

		is($res, $max, 'mode max');
	},

	'mode last' => sub {
		my $n = int(rand 10) + 1;

		my $v;
		my $res;

		for (1 .. $n) {
			$v = int(rand 100) - int(rand 100);
			$res = metric_send(8097, 'angie', $v);
		}

		is($res, $v, 'mode last');
	},

	'mode gauge' => sub {
		my $n = int(rand 10) + 1;

		my $res;
		my $gauge = 0;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			$gauge += $v;

			$res = metric_send(8098, 'angie', $v);
		}

		is($res, $gauge, 'mode gauge');
	},

	'mode avg (count)' => sub {
		my @vals;

		my @res;
		my $n = int(rand 10) + 3;

		for my $i (1 .. $n) {
			my $v = rand(100) - rand(100);

			push @vals, $v;

			# count=3, default count=10
			my $j = $i < 3  ? $i : 3;
			my $k = $i < 10 ? $i : 10;

			@res = split(';', metric_send(8099, 'angie', $v));

			my $res_base  = $res[0];
			my $res_count = $res[1];

			my $avg_base  = sum(@vals[-$k .. -1]) / $k;
			my $avg_count = sum(@vals[-$j .. -1]) / $j;

			cmp_deeply($res_base,  num($avg_base, TOLERANCE),
				"mode avg (base) $i");
			cmp_deeply($res_count, num($avg_count, TOLERANCE),
				"mode avg (count) $i");
		}
	},

	'mode avg (window)' => sub {
		my $v1 = rand(1000) - rand(1000);
		my $v2 = rand(1000) - rand(1000);

		my $avg = ($v1 + $v2) / 2;

		metric_send(8100, '', $v1);
		my @res = split(';', metric_send(8100, '', $v2));

		cmp_deeply($res[0], num($avg, TOLERANCE), 'mode avg (base) 1');
		is($res[0], $res[1], 'mode avg (window) 1');

		# window=1s
		select undef, undef, undef, 1.5;

		my $v3 = rand(1000) - rand(1000);
		$avg = ($v1 + $v2 + $v3) / 3;

		@res = split(';', metric_send(8100, '', $v3));

		cmp_deeply($res[0], num($avg, TOLERANCE), 'mode avg (base) 2');
		isnt($res[0], $res[1], 'mode avg (window) 2');
	},

	'mode avg exp' => sub {
		my $res;

		my $tmp = rand(100) - rand(100);
		metric_send(8101, 'angie', $tmp);

		for (1 .. 3) {
			my $v = rand(100) - rand(100);

			$res = metric_send(8101, 'angie', $v);

			# factor=80
			$tmp += 0.8 * ($v - $tmp);
		}

		cmp_deeply($res, num($tmp, TOLERANCE), 'mode avg exp 1');

		$tmp = rand(100) - rand(100);
		metric_send(8102, 'angie', $tmp);

		for (1 .. 3) {
			my $v = rand(100) - rand(100);

			$res = metric_send(8102, 'angie', $v);

			# factor=20
			$tmp += 0.2 * ($v - $tmp);
		}

		cmp_deeply($res, num($tmp, TOLERANCE), 'mode avg exp 2');
	},

	'mode hist' => sub {
		my @buckets = (0.1, 2, 5, 8, 10, 'inf');

		my %hist = map {$_ => 0} @buckets;

		for (1 .. 10) {
			my $v = rand(11);

			my @res = split(';', metric_send(8103, "angie", $v));

			my @res1 = sort split(' ', $res[0]);
			my @res2 = sort split(' ', $res[1]);

			for my $k (@buckets) {
				if ($k eq 'inf' || $v <= $k) {
					$hist{$k}++;
				}
			}

			my @exp = sort values %hist;

			cmp_deeply(\@res1, \@exp, "mode hist 1 - $_");
			cmp_deeply(\@res2, \@exp, "mode hist 2 - $_");
		}
	},

	'complex var' => sub {
		metric_send(8104, 'angie', 0);
		metric_send(8104, 'angie', 20);
		my $res = metric_send(8104, 'angie', 40);

		like(
			$res,
			qr/^3, 20, 1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 3$/m,
			"complex variable"
		);
	},

	'stage' => sub {
		plan(skip_all => 'no http api') unless $t->has_module('http_api');

		metric_send(8105, 'angie', 1);
		is(get_json('/api/stage1/metrics/angie/'), 0, 'stage connect 1');

		metric_send(8106, 'angie', 1);
		like(http_get('/api/stage1/metrics/'), qr/"angie":\s\d+/,
			'stage connect 2');

		SKIP: {
			skip 'no mqtt preread', 1
				if not $t->has_module('stream_mqtt_preread');

			my $packet = mqtt_connect(5, 'angie', '');
			stream('127.0.0.1:' . port(8107))->io($packet);

			is(get_json('/api/stage2/metrics/angie/'), 1, 'stage preread');
		}

		metric_send(8108, 'angie', 1);
		is(get_json('/api/stage3/metrics/angie/'), 9, 'stage end');
	},

	'complex metrics - basic' => sub {
		plan(skip_all => 'no http api') unless $t->has_module('http_api');

		my $key = 'a' x 255;

		metric_send(8109, $key, 0);
		my $res = get_json("/api/block0/metrics");

		cmp_deeply(
			$res->{"$key..."},
			{
				count => 1,
				min   => 0,
				max   => 0,
				last  => 0,
				gauge => 0,
				avg   => 0,
				hist  => {
					1  => 1,
					5  => 1,
					10 => 1
				}
			},
			'large key'
		) or diag(explain({got => $res}));

		my $n = int(rand 250) + 1;

		$key = 'a' x $n;

		metric_send(8109, $key, 0);
		$res = get_json("/api/block0/metrics/$key/");

		cmp_deeply(
			$res,
			{
				count => 1,
				min   => 0,
				max   => 0,
				last  => 0,
				gauge => 0,
				avg   => 0,
				hist  => {
					1  => 1,
					5  => 1,
					10 => 1
				}
			},
			'block 1'
		) or diag(explain({got => $res}));

		metric_send(8109, $key, 348);
		$res = get_json("/api/block0/metrics/$key/");

		cmp_deeply(
			$res,
			{
				count => 2,
				min   => 0,
				max   => 348,
				last  => 348,
				gauge => 348,
				avg   => 174,
				hist  => {
					1  => 1,
					5  => 1,
					10 => 1
				}
			},
			'block 2'
		) or diag(explain({got => $res}));

		metric_send(8109, $key, -343455);
		$res = get_json("/api/block0/metrics/$key/");

		cmp_deeply(
			$res,
			{
				count => 3,
				min   => -343455,
				max   => 348,
				last  => -343455,
				gauge => -343107,
				avg   => -114369,
				hist => {
					1  => 2,
					5  => 2,
					10 => 2
				}
			},
			'block 3'
		) or diag(explain({got => $res}));

		metric_send(8109, $key, 0.04);
		$res = get_json("/api/block0/metrics/$key/");

		cmp_deeply(
			$res,
			{
				count => 4,
				min   => -343455,
				max   => 348,
				last  => 0.04,
				gauge => -343106.96,
				avg   => -85776.74,
				hist  => {
					1  => 3,
					5  => 3,
					10 => 3
				}
			},
			'block 4'
		) or diag(explain({got => $res}));

		metric_send(8109, '"91A,&man', 1);
		$res = get_json('/api/block0/metrics/"91A,&man/');

		cmp_deeply(
			$res,
			{
				count => 1,
				min   => 1,
				max   => 1,
				last  => 1,
				gauge => 1,
				avg   => 1,
				hist  => {
					1  => 1,
					5  => 1,
					10 => 1
				}
			},
			"hash collision 1"
		);

		# crc32("91A,&man) == crc32(O~~yX}}12)
		metric_send(8109, 'O~~yX}}12', 1);
		my $res2 = get_json("/api/block0/metrics/O~~yX}}12/");

		cmp_deeply($res, $res2, "hash collision 2");
	},

	'api output' => sub {
		plan(skip_all => 'no http api') unless $t->has_module('http_api');

		for (my $i = 1; $i < 109; $i++) {
			metric_send(8110, 'angie', $i);
		}

		my %hist1;

		for (my $i = 1; $i < 109; $i++) {
			$hist1{$i} = $i;
			is(get_json("/api/block_large_slabs/metrics/angie/hist/$i"), $i,
				"api output $i");
		}

		my $res = get_json("/api/block_large_slabs/metrics/angie/hist");

		cmp_deeply($res, \%hist1, 'api output 108')
			or diag(explain({got => $res}));

		is(get_json("/api/block_large_slabs/metrics/angie/count"), 108,
			'api output 109');
		is(get_json("/api/block_large_slabs/metrics/angie/min"), 1,
			'api output 110');
		is(get_json("/api/block_large_slabs/metrics/angie/max"), 108,
			'api output 111');
		is(get_json("/api/block_large_slabs/metrics/angie/last"), 108,
			'api output 112');
		is(get_json("/api/block_large_slabs/metrics/angie/gauge"), 5886,
			'api output 113');
		is(get_json("/api/block_large_slabs/metrics/angie/avg"), 58.5,
			'api output 114');
		is(get_json("/api/block_large_slabs/metrics/angie/hist2/1"), 1,
			'api output 115');
		is(get_json("/api/block_large_slabs/metrics/angie/hist2/2"), 2,
			'api output 116');
		is(get_json("/api/block_large_slabs/metrics/angie/hist2/3"), 3,
			'api output 117');
		is(get_json("/api/block_large_slabs/metrics/angie/hist2/4"), 4,
			'api output 118');
		is(get_json("/api/block_large_slabs/metrics/angie/hist2/5"), 5,
			'api output 119');

		$res = get_json("/api/block_large_slabs/metrics/angie/hist2");

		cmp_deeply(
			$res,
			{
				1 => 1,
				2 => 2,
				3 => 3,
				4 => 4,
				5 => 5
			},
			'api output 120'
		) or diag(explain({got => $res}));
	},

	'complex metrics - expire on' => sub {
		plan(skip_all => 'no http api') unless $t->has_module('http_api');

		my @block1_data;

		my $fails = 0;
		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. int(rand 200) + 2);

			my $v = int(rand 99999) - int(rand 99999);

			metric_send(8111, $key, $v);
			push @block1_data, get_json("/api/block1/metrics/$key");

			$fails = get_json('/api/status/slabs/block1/slots/128/fails');
		} while ($fails < 10);

		my $res = get_json('/api/block1/metrics');
		ok(defined $res->{expired}, 'expire on with key 1');

		my $expired = $res->{expired};

		my @buckets = (1, 500, 1000, 10000);
		my $data1 = shift @block1_data;
		foreach my $block1_elem (@block1_data) {
			$data1->{count} += $block1_elem->{count};

			if ($data1->{min} > $block1_elem->{min}) {
				$data1->{min} = $block1_elem->{min};
			}

			if ($data1->{max} < $block1_elem->{max}) {
				$data1->{max} = $block1_elem->{max};
			}

			$data1->{last} = $block1_elem->{last};
			$data1->{gauge} += $block1_elem->{gauge};

			$data1->{avg1} += 0.9 * ($data1->{last} - $data1->{avg1});

			foreach my $bucket (@buckets) {
				$data1->{hist}{$bucket} += $block1_elem->{hist}{$bucket};
			}

			last if $data1->{count} >= $expired->{count}
				&& $data1->{gauge} >= $expired->{gauge};
		}

		# Skip average mean
		$data1->{avg2} = ignore();
		$data1->{avg3} = ignore();

		$data1->{avg1} = num($data1->{avg1}, TOLERANCE);

		cmp_deeply($expired, $data1, 'expire on with key 2')
			or diag(explain({got => $expired, expected => $data1}));

		my @block2_data;

		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. 30);

			my $v = rand 99999 - rand 99999;

			metric_send(8112, $key, $v);
			push @block2_data, $key;

			$fails = get_json('/api/status/slabs/block2/slots/128/fails');
		} while ($fails < 100);

		$fails = 0;

		foreach my $key (@block2_data) {
			my $res = get_json("/api/block2/metrics/$key");

			if (exists $res->{error}) {
				$fails++;
			}
		}

		is($fails, 100, 'expire on without key');

		# complex metrics - submetric vars
		is(metric_send(8113, 'expired', 0), $data1->{count}, 'count');
		is(metric_send(8114, 'expired', 0), $data1->{min}, 'min');
		is(metric_send(8115, 'expired', 0), $data1->{max}, 'max');
		is(metric_send(8116, 'expired', 0), $data1->{last}, 'last');

		my @hist_items = map { $data1->{hist}{$_} } @buckets;
		my $hist_str = join(" ", @hist_items);

		is(metric_send(8117, 'expired', 0), $hist_str, 'histogram');
		is(metric_send(8118, 'expired', 0), $data1->{gauge}, 'gauge');
	},

	'complex metrics - expire off' => sub {
		plan(skip_all => 'no http api') unless $t->has_module('http_api');

		my $fails = 0;
		my $count = 0;
		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. int(rand 200) + 2);

			my $v = int(rand 999999);

			metric_send(8119, $key, $v);
			my $res = get_json("/api/block3/metrics/$key/");

			if (exists $res->{error}) {
				$count++;
			}

			$fails = get_json('/api/status/slabs/block3/slots/128/fails');
		} while ($fails < 100);

		is($count, 100, 'expire off without key');

		my $data = {
			count => 0,
			min   => 99999999,
			max   => -99999999,
			last  => 0,
			gauge => 0,
			hist  => {
				1  => 0,
				5  => 0,
				10 => 0
			}
		};

		my $res;
		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. 200);

			my $v = int(rand 10);

			metric_send(8120, $key, $v);
			my $res = get_json("/api/block4/metrics/$key/");

			if (exists $res->{error}) {
				$data->{count}++;

				if ($data->{min} > $v) {
					$data->{min} = $v;
				}

				if ($data->{max} < $v) {
					$data->{max} = $v;
				}

				$data->{last} = $v;
				$data->{gauge} += $v;

				foreach my $bucket (1, 5, 10) {
					if ($bucket >= $v) {
						$data->{hist}{$bucket}++;
					}
				}
			}

			$fails = get_json('/api/status/slabs/block4/slots/128/fails');
		} while ($fails < 10);

		# Skip average mean
		$data->{avg} = ignore();

		my $expired = get_json('/api/block4/metrics/some_key');

		cmp_deeply($expired, $data, 'expire off with key')
			or diag(explain({got => $expired}));

		my $discarded = get_json('/api/block4/discarded');

		is($discarded, $expired->{'count'}, 'discarded count');
	},
);

$t->plan(scalar keys %test_cases);

$t->run_tests(\%test_cases);

###############################################################################

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

sub mqtt_connect {
	my ($version, $client_id, $username) = @_;
	my ($ul, $cl) = (length($username) , length($client_id));

	my ($f) = 2;
	$f |= 0x80 if $ul;

	my ($vh) = pack('nNC2n', 0x04, 0x4d515454, $version, $f, 0x00);
	$vh .= pack('c', 0x00) if $version eq 5;

	my $p = pack('n', $cl) . $client_id;
	$p .= pack('n', $ul) . $username if $ul;
	$vh .= $p;

	my $packet = pack('C', 0x10);
	$packet .= get_varbyte(length($vh)) . $vh;

	return $packet;
}

sub get_varbyte {
	my ($x) = @_;
	my ($b, $o);

	do {
		$b = $x % 128;
		$x = int($x / 128);
		$b = $b | 128 if $x > 0;
		$o .= pack('C', $b)
	} while ($x > 0);

	return $o;
}
