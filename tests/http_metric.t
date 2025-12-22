#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for http_metric module.

###############################################################################

use warnings;
use strict;

use List::Util qw/ sum /;
use Test::More;
use Test::Deep qw/ cmp_deeply num ignore superhashof /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/ get_json /;

###############################################################################

use constant 'TOLERANCE' => 1e-6;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_api http_metric rewrite/);

my $conf = <<'EOF'

%%TEST_GLOBALS%%

daemon off;

events {
}

worker_processes 4;

http {
    %%TEST_GLOBALS_HTTP%%

    variables_hash_bucket_size 128;

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
    metric_zone stage1:128k last;
    metric_zone stage2:128k last;
    metric_zone stage3:128k last;
    metric_zone stage_redirect:128k count;

    metric_complex_zone complex_var:128k {
        count count;
        avg   average mean count=40;
        hist  histogram 1 2 3 10 11 12 13 14 15 16 17 18 19 20 21 22 23 34 90;
    }

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
        listen 127.0.0.1:8080;

        location ~ /var1/(.+)/(.+)$ {
            set $metric_var $1=$2;
            return 200 "$metric_var;$metric_var_key;$metric_var_value";
        }

        location ~ /var2/(.+)/(.*)$ {
            set $metric_var_key   $1;
            set $metric_var_value $2;
            return 200 "$metric_var;$metric_var_key;$metric_var_value";
        }

        location /stage/request1/ {
            metric stage1 $request_completion=$bytes_sent on=request;
            api /status/http/metric_zones/stage1;
        }

        location /stage/request2/ {
            metric stage1 angie=$request_length on=request;
            api /status/http/metric_zones/stage1;
        }

        location /stage/response/ {
            metric stage2 angie=$request_length on=response;
            api /status/http/metric_zones/stage2;
        }

        location /stage/end/ {
            metric stage3 $request_completion=$bytes_sent on=end;
            api /status/http/metric_zones/stage3;
        }

        location /counter/ {
            metric counter counter;
            return 200 OK;
        }
        location /counter/request/ {
            metric counter counter1 on=request;
            return 200 OK;
        }
        location /counter/response/ {
            metric counter counter2 on=response;
            return 200 OK;
        }
        location /counter/end/ {
            metric counter counter3 on=end;
            return 200 OK;
        }

        location ~ ^/min/(.+)$ {
            metric min angie=$1;
            return 200 OK;
        }

        location ~ ^/max/(.+)$ {
            metric max angie=$1;
            return 200 OK;
        }

        location ~ ^/last/(.+)$ {
            metric last angie=$1;
            return 200 OK;
        }

        location ~ ^/gauge/(.+)$ {
            metric gauge angie=$1;
            return 200 OK;
        }

        location ~ ^/avg1/(.+)$ {
            metric avg0 avg1_base=$1;
            metric avg1 count=$1;
            return 200 OK;
        }

        location ~ ^/avg2/(.+)$ {
            metric avg0 avg2_base=$1;
            metric avg2 window=$1;
            return 200 OK;
        }

        location ~ ^/avg_exp1/(.+)$ {
            metric avg_exp1 angie=$1;
            return 200 OK;
        }

        location ~ ^/avg_exp2/(.+)$ {
            metric avg_exp2 angie=$1;
            return 200 OK;
        }

        location ~ ^/hist/(.+)$ {
            metric hist1 angie=$1;
            metric hist2 angie=$1;
            return 200 OK;
        }

        location ~ ^/block0/(.+)/(.*)$ {
            metric block0 $1=$2 on=request;
            api /status/http/metric_zones/block0/metrics/$1;
        }

        location ~ ^/block_large_slabs/(.*)$ {
            metric block_large_slabs angie=$1;
        }

        location ~ ^/complex_var/(.+)$ {
            set $metric_complex_var_key "angie";
            set $metric_complex_var_value $1;
            return 200 "value=$metric_complex_var_value";
        }

        location ~ ^/block1/(.+)/(.*)$ {
            metric block1 $1=$2 on=request;
            api /status/http/metric_zones/block1/metrics/$1;
        }

        location /var/block1/count/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_count";
        }

        location /var/block1/min/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_min";
        }

        location /var/block1/max/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_max";
        }

        location /var/block1/last/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_last";
        }

        location /var/block1/hist/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_hist";
        }

        location /var/block1/gauge/ {
            set $metric_block1_key expired;
            return 200 "value=$metric_block1_value_gauge";
        }

        location ~ ^/block2/(.+)/(.*)$ {
            set $metric_block2 $1=$2;
            api /status/http/metric_zones/block2/metrics/$1;
        }

        location ~ ^/block3/(.+)/(.*)$ {
            set $metric_block3_key $1;
            set $metric_block3_value $2;
            api /status/http/metric_zones/block3/metrics/$1;
        }

        location ~ ^/block4/(.+)/(.*)$ {
            metric block4 $1=$2 on=request;
            api /status/http/metric_zones/block4/metrics/$1;
        }

        location /api/ {
            allow 127.0.0.1;
            deny  all;

            location /api/status/ {
                api /status/;
            }

            api /status/http/metric_zones/;
        }

EOF
;

if ($t->has_module('image_filter')) {
	$conf .= <<'EOF'
        location /error {
            metric stage_redirect err_req on=request;
            metric stage_redirect err_res on=response;
            metric stage_redirect err_end on=end;

            add_header Content-Type text/plain;
            return 200 "error\n";
        }

        location /redirect1/ {
            error_page 415 = /error;
            alias %%TESTDIR%%/;

            metric stage_redirect ok_req on=request;
            metric stage_redirect ok_res on=response;
            metric stage_redirect ok_end on=end;

            image_filter resize 100000 100000;
        }

        location /redirect2/ {
            error_page 415 = /error;
            alias %%TESTDIR%%/;

            metric stage_redirect ok_req on=request;
            metric stage_redirect ok_res on=response;
            metric stage_redirect ok_end on=end;

            image_filter resize 100000 100000;

            return 200 "ok\n";
        }
EOF
;
}

$conf .= "    }\n}";

$t->write_file_expand('nginx.conf', $conf);

$t->run();

###############################################################################

my %test_cases = (
	'api metric tree' => sub {
		my $res = get_json('/api/status/');
		cmp_deeply(
			$res->{http}{metric_zones},
			superhashof({}),
			'api metric tree'
		);
	},

	'variables' => sub {
		like(http_get("/var1/angie/tt"),  qr/^angie=tt;angie;1$/m,
			'variables 1 - 1');
		like(http_get("/var1/angie/-1"),  qr/^angie=-1;angie;2$/m,
			'variables 1 - 2');
		like(http_get("/var1/angie/0.1"), qr/^angie=0\.1;angie;3$/m,
			'variables 1 - 3');
		like(http_get("/var1/foo/11"),    qr/^foo=11;foo;1$/m,
			'variables 1 - 4');
		like(http_get("/var1/foo/0"),     qr/^foo=0;foo;2$/m,
			'variables 1 - 5');

		like(http_get("/var2/angie/tt"),  qr/^angie=tt;angie;4$/m,
			'variables 2 - 1');
		like(http_get("/var2/angie/-1"),  qr/^angie=-1;angie;5$/m,
			'variables 2 - 2');
		like(http_get("/var2/angie/0.1"), qr/^angie=0\.1;angie;6$/m,
			'variables 2 - 3');
		like(http_get("/var2/foo/11"),    qr/^foo=11;foo;3$/m,
			'variables 2 - 4');
		like(http_get("/var2/foo/0"),     qr/^foo=0;foo;4$/m,
			'variables 2 - 5');
	},

	'stage' => sub {
		like(http_get('/stage/request1/'), qr/{}/,
			'stage request 1');
		like(http_get('/stage/request2/'), qr/"angie":\s\d+/,
			'stage request 2');

		like(http_get('/stage/response/'), qr/{}/, 'stage response');

		like(http_get('/stage/end/'), qr/{}/,
			'stage end 1');
		like(http_get('/api/stage3/'),      qr/"OK":\s\d+/,
			'stage end 2');

	SKIP: {
		skip 'no image filter', 2 if not $t->has_module('image_filter');

		$t->write_file('test', 'angie');

		http_get('/redirect1/test');
		my $res = get_json('/api/stage_redirect/metrics/');

		cmp_deeply(
			$res,
			{
				ok_req => 1,
				err_res => 1,
				err_end => 1
			},
			'stage redirect 1'
		) or diag(explain({got => $res}));

		http_get('/redirect2/test');
		$res = get_json('/api/stage_redirect/metrics/');

		cmp_deeply(
			$res,
			{
				ok_req => 2,
				err_res => 2,
				err_end => 2
			},
			'stage redirect 2'
		) or diag(explain({got => $res}));
	}
	},

	'mode counter' => sub {
		my $n = int(rand 10) + 1;

		for (1 .. $n) {
			http_get('/counter/');
			http_get('/counter/request/');
			http_get('/counter/response/');
			http_get('/counter/end/');
		}

		my $api_res = get_json('/api/counter/metrics');
		is($api_res->{counter}, $n, 'mode counter - default "on" (end)');
		ok(defined $api_res->{counter1}, 'mode counter - on=request');
		ok(defined $api_res->{counter2}, 'mode counter - on=response');
		is($api_res->{counter3}, $n, 'mode counter - on=end');
	},

	'mode min' => sub {
		my $n = int(rand 10) + 1;

		my $min = 99999;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			if ($min > $v) {
				$min = $v;
			}

			http_get("/min/$v");
		}

		is(get_json('/api/min/metrics/angie'), $min, 'mode min');
	},

	'mode max' => sub {
		my $n = int(rand 10) + 1;

		my $max = -99999;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			if ($max < $v) {
				$max = $v;
			}

			http_get("/max/$v");
		}

		is(get_json('/api/max/metrics/angie'), $max, 'mode max');
	},

	'mode last' => sub {
		my $n = int(rand 10) + 1;

		my $v;
		for (1 .. $n) {
			$v = int(rand 100) - int(rand 100);
			http_get("/last/$v");
		}

		is(get_json('/api/last/metrics/angie'), $v, 'mode last');
	},

	'mode gauge' => sub {
		my $n = int(rand 10) + 1;

		my $gauge = 0;

		for (1 .. $n) {
			my $v = int(rand 100) - int(rand 100);

			$gauge += $v;

			http_get("/gauge/$v");
		}

		is(get_json('/api/gauge/metrics/angie'), $gauge, 'mode gauge');
	},

	'mode avg (count)' => sub {
		my @vals;

		my $n = int(rand 10) + 3;

		for my $i (1 .. $n) {
			my $v = rand(100) - rand(100);

			push @vals, $v;

			# count=3, default count=10
			my $j = $i < 3  ? $i : 3;
			my $k = $i < 10 ? $i : 10;

			http_get("/avg1/$v");

			my $res_base  = get_json('/api/avg0/metrics/avg1_base');
			my $res_count = get_json('/api/avg1/metrics/count');

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

		http_get("/avg2/$v1");
		http_get("/avg2/$v2");

		my $avg = ($v1 + $v2) / 2;

		my $avg_base = get_json('/api/avg0/metrics/avg2_base');

		cmp_deeply($avg_base, num($avg, TOLERANCE), 'mode avg (base) 1');
		is($avg_base, get_json('/api/avg2/metrics/window'),
			'mode avg (window) 1');

		# window=1s
		select undef, undef, undef, 1.5;

		my $v3 = rand(1000) - rand(1000);
		http_get("/avg2/$v3");

		$avg = ($v1 + $v2 + $v3) / 3;

		$avg_base = get_json('/api/avg0/metrics/avg2_base');

		cmp_deeply($avg_base, num($avg, TOLERANCE), 'mode avg (base) 2');
		isnt($avg_base, get_json('/api/avg2/metrics/window'),
			'mode avg (window) 2');
	},

	'mode avg exp' => sub {
		my $tmp = rand(100) - rand(100);
		http_get("/avg_exp1/$tmp");

		for (1 .. 3) {
			my $v = rand(100) - rand(100);

			http_get("/avg_exp1/$v");

			# factor=80
			$tmp += 0.8 * ($v - $tmp);
		}

		cmp_deeply(
			get_json('/api/avg_exp1/metrics/angie'),
			num($tmp, TOLERANCE),
			'mode avg exp 1'
		);

		$tmp = rand(100) - rand(100);
		http_get("/avg_exp2/$tmp");

		for (1 .. 3) {
			my $v = rand(100) - rand(100);

			http_get("/avg_exp2/$v");

			# factor=20
			$tmp += 0.2 * ($v - $tmp);
		}

		cmp_deeply(
			get_json('/api/avg_exp2/metrics/angie'),
			num($tmp, TOLERANCE),
			'mode avg exp 2'
		);
	},

	'mode hist' => sub {
		my @buckets = (0.1, 2, 5,  8, 10, 'inf');

		my %hist = map {$_ => 0} @buckets;

		for (1 .. 10) {
			my $v = rand(11);

			http_get("/hist/$v");

			for my $k (@buckets) {
				if ($k eq 'inf' || $v <= $k) {
					$hist{$k}++;
				}
			}

			cmp_deeply(get_json('/api/hist1/metrics/angie'), \%hist,
				"mode hist 1 - $_");
			cmp_deeply(get_json('/api/hist2/metrics/angie'), \%hist,
				"mode hist 2 - $_");
		}
	},

	'complex metrics - basic' => sub {
		my $key = 'a' x 255;

		http_get("/block0/$key.../");
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

		$res = get_json("/block0/$key/");

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

		$res = get_json("/block0/$key/348");

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

		$res = get_json("/block0/$key/-343455");

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

		$res = get_json("/block0/$key/0.04");

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

		$res = get_json('/block0/"91A,&man/1');

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

		cmp_deeply($res, get_json("/block0/O~~yX}}12/1"), "hash collision 2");
	},

	'api output' => sub {
		for (my $i = 1; $i < 109; $i++) {
			http_get("/block_large_slabs/$i");
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

	'complex var' => sub {
		http_get('/complex_var/0');
		http_get('/complex_var/20');

		like(
			http_get("/complex_var/40"),
			qr/^value=3, 20, 1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 3$/m,
			"complex variable"
		);
	},

	'complex metrics - expire on' => sub {
		my @block1_data;

		my $fails = 0;
		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. int(rand 200) + 2);

			my $v = int(rand 99999) - int(rand 99999);

			push @block1_data, get_json("/block1/$key/$v");

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

		cmp_deeply($expired, $data1, 'expire on with key 2')
			or diag(explain({got => $expired}));

		my @block2_data;

		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. 30);

			my $v = rand 99999 - rand 99999;

			http_get("/block2/$key/$v");
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
		like(http_get('/var/block1/count/'), qr/value=$data1->{count}/,
			'count');
		like(http_get('/var/block1/min/'), qr/value=$data1->{min}/, 'min');
		like(http_get('/var/block1/max/'), qr/value=$data1->{max}/, 'max');
		like(http_get('/var/block1/last/'), qr/value=$data1->{last}/, 'last');

		my @hist_items = map { $data1->{hist}{$_} } @buckets;
		my $hist_str = join(" ", @hist_items);

		like(http_get('/var/block1/hist/'), qr/value=$hist_str/, 'hist');
		like(http_get('/var/block1/gauge/'), qr/value=$data1->{gauge}/,
			'gauge');
	},

	'complex metrics - expire off' => sub {
		my $fails = 0;
		my $count = 0;
		do {
			my $key = '';
			$key .= sprintf("%x", rand 16) for (1 .. int(rand 200) + 2);

			my $v = int(rand 999999);

			my $res = get_json("/block3/$key/$v");

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

			my $res = get_json("/block4/$key/$v");

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
