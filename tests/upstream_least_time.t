#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for upstream least_time balancer module.
# TODO: account with probes

###############################################################################

use warnings;
use strict;

use Test::Deep qw/cmp_deeply cmp_details deep_diag/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant REQUESTS => 100;

my $response = 'OK' x 500;

my $t = Test::Nginx->new()
	->has(qw/upstream_least_time upstream_zone map/)
	->has(qw/http http_api http_perl/);

# for http_perl_module
plan(skip_all => 'perl >= 5.6.1 required')
	if $t->has_module('perl') && $] < 5.006001;

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    perl_modules %%TESTDIR%%;
    perl_require helper.pm;

    map const \$lt_account_const {
        default 1;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /api/ {
            api /;
        }

        location /u {
            proxy_pass http://\$arg_upstream;
        }
    }

    upstream u1 {
        zone z1 1m;
        least_time header;
        server 127.0.0.1:8071;
        server 127.0.0.1:8072;
    }
    upstream u3 {
        zone z3 1m;
        least_time header account=\$lt_account_const;
        server 127.0.0.1:8071;
        server 127.0.0.1:8072;
    }
    server {
        listen 127.0.0.1:8071;

        location / {
            set \$port %%PORT_8071%%;
            set \$delay 10;
            perl helper::handler;
        }
    }
    server {
        listen 127.0.0.1:8072;

        location / {
            set \$port %%PORT_8072%%;
            set \$delay 100;
            perl helper::handler;
        }
    }

    upstream u2 {
        zone z2 1m;
        least_time last_byte;
        server 127.0.0.1:8073;
        server 127.0.0.1:8074;
    }
    upstream u4 {
        zone z4 1m;
        least_time last_byte account=\$lt_account_const;
        server 127.0.0.1:8073;
        server 127.0.0.1:8074;
    }
    server {
        listen 127.0.0.1:8073;

        location / {
            limit_rate 1000;
            return 200 %%PORT_8073%%$response;
        }
    }
    server {
        listen 127.0.0.1:8074;

        location / {
            limit_rate 1500;
            return 200 %%PORT_8074%%$response;
        }
    }
}

EOF

# helper module for 'header' tests
$t->write_file_expand('helper.pm', <<'EOF');
package helper;

use nginx;

sub handler {
    my $r = shift;
    my $delay = $r->variable("delay");
    $r->send_http_header();
    $r->sleep($delay, \&next);
}

sub next {
    my $r = shift;
    $r->print($r->variable("port"));
    return OK;
}

1;
EOF

$t->run();

my ($port1, $port2, $port3, $port4)
	= (port(8071), port(8072), port(8073), port(8074));

my %test_cases = (

	'header' => {
		test_sub    => \&test_balancer,
		test_params => {
			upstream_name => 'u1',
			peers         => [$port1, $port2],
			expected      => {
				requests => [$port2, $port1],
				api => sub {
					my $got = shift;

					# expected:
					#	port1:
					#		header_time   => 10
					#		response_time => 10
					#	port2:
					#		header_time   => 100
					#		response_time => 100

					return (0, "$port1: header_time < 10 (delay)")
						if $got->{$port1}{header_time} < 10;

					return (0, "$port2: header_time < 100 (delay)")
						if $got->{$port2}{header_time} < 100;

					return (0, "$port1 response_time > $port2 response_time")
						if $got->{$port1}{response_time}
							> $got->{$port2}{response_time};

					return 1;
				},
			},
		},
	},
	'header with account' => {
		test_sub    => \&test_balancer,
		test_params => {
			upstream_name => 'u3',
			peers         => [$port1, $port2],
			expected      => {
				requests => [$port2, $port1],
				api => sub {
					my $got = shift;

					# expected:
					#	port1:
					#		header_time   => 10
					#		response_time => 10
					#	port2:
					#		header_time   => 100
					#		response_time => 100

					return (0, "$port1: header_time < 10 (delay)")
						if $got->{$port1}{header_time} < 10;

					return (0, "$port2: header_time < 100 (delay)")
						if $got->{$port2}{header_time} < 100;

					return (0, "$port1 response_time > $port2 response_time")
						if $got->{$port1}{response_time}
							> $got->{$port2}{response_time};

					return 1;
				},
			},
		},
	},

	'last_byte'  => {
		test_sub    => \&test_balancer,
		test_params => {
			upstream_name => 'u2',
			peers         => [$port3, $port4],
			expected      => {
				requests => [$port3, $port4],
				api => sub {
					my $got = shift;

					# expected:
					#	port3:
					#		header_time   => 1
					#		response_time => 1000
					#	port4:
					#		header_time   => 1
					#		response_time => 1

					return (0, "$port3: response_time < 1000 (limit_rate)")
						if $got->{$port3}{response_time} < 1000;

					return (0, "$port4: response_time != header_time")
						if $got->{$port4}{response_time}
							!= $got->{$port4}{header_time};

					return (0, "$port3 response_time < $port4 response_time")
						if $got->{$port3}{response_time}
							< $got->{$port4}{response_time};

					return 1;
				},
			},
		},
	},
	'last_byte with account'  => {
		test_sub    => \&test_balancer,
		test_params => {
			upstream_name => 'u4',
			peers         => [$port3, $port4],
			expected      => {
				requests => [$port3, $port4],
				api => sub {
					my $got = shift;

					# expected:
					#	port3:
					#		header_time   => 1
					#		response_time => 1000
					#	port4:
					#		header_time   => 1
					#		response_time => 1

					return (0, "$port3: response_time < 1000 (limit_rate)")
						if $got->{$port3}{response_time} < 1000;

					return (0, "$port4: response_time != header_time")
						if $got->{$port4}{response_time}
							!= $got->{$port4}{header_time};

					return (0, "$port3 response_time < $port4 response_time")
						if $got->{$port3}{response_time}
							< $got->{$port4}{response_time};

					return 1;
				},
			},
		},
	},
);

$t->plan(scalar keys %test_cases);

$t->run_tests(\%test_cases);

###############################################################################

sub test_balancer {
	my ($t, $test_params) = @_;

	my $balancer_stat = collect_balancer_stat($test_params);

	my $expected = $test_params->{expected};

	if (defined $expected->{requests}) {
		my @requests_share = sort {
			$balancer_stat->{$a} <=> $balancer_stat->{$b}
		} keys %{ $balancer_stat };

		cmp_deeply(\@requests_share, $expected->{requests},
			'distibution of requests across peers')
			or diag(explain({
				got => \@requests_share,
				expected => $expected->{requests},
				balancer_stat => $balancer_stat
			}));
	}

	my $api_stat = collect_api_stat($test_params->{upstream_name});

	cmp_deeply($api_stat->{requests}, $balancer_stat, 'requests api stat')
		or diag(explain({
			api_requests      => $api_stat->{requests},
			balancer_requests => $balancer_stat,
		}));

	my ($api_ok, $reason) = test_api_response($api_stat->{health},
		$expected->{api}, $test_params->{peers});
	ok($api_ok, 'health api stat')
		or diag(explain({
			health_got => $api_stat->{health},
			reason => $reason
		}));
}

sub test_api_response {
	my ($got, $expected, $peers) = @_;

	my %expected_api = map {
		$_ => {
			header_time   => $NUM_RE,
			response_time => $NUM_RE,
		},
	} @{ $peers };
	my ($ok, $stack) = cmp_details($got, \%expected_api);
	return (0, deep_diag($stack))
		unless $ok;

	my ($p1, $p2) = @{ $peers };

	return (0, "$p1: response_time < header_time")
		if $got->{$p1}{response_time} < $got->{$p1}{header_time};

	return (0, "$p2: response_time < header_time")
		if $got->{$p2}{response_time} < $got->{$p2}{header_time};

	if (defined $expected && ref $expected eq 'CODE') {
		return $expected->($got);
	}

	return 1;
}

###############################################################################

sub collect_balancer_stat {
	my $test_params = shift;

	my %balancer_stat = map {$_ => 0} @{ $test_params->{peers} };

	note("\n");

	for my $i (1 .. REQUESTS) {

		my $output = http_get('/u?upstream=' . $test_params->{upstream_name});
		note("output: '$output', length: " . length($output));

		if ($output && $output =~ /^(\d{4})/m) {
			my $port = $1;

			$balancer_stat{$port} //= 0;
			$balancer_stat{$port}++;

			my $stat = get_json('/api/status/http/upstreams/'
				. "$test_params->{upstream_name}/peers/127.0.0.1:$port");
			note("test_case\t$test_params->{test_case_name}#$i\t$port\t"
				. "header=$stat->{health}{header_time}\t"
				. "response=$stat->{health}{response_time}"
			);
			note("\n");

		} else {
			diag("not registered request: '$output', length: "
				. length($output));
		}
	}

	note(explain({balancer_stat => \%balancer_stat}));

	return \%balancer_stat;
}

sub collect_api_stat {
	my $upstream_name = shift;

	my $stat = get_json("/api/status/http/upstreams/$upstream_name/peers/");
	note(explain({full_stat => $stat}));

	my %api_stat;
	while (my ($peer, $peer_stat) = each (%{ $stat })) {
		(my $port) = $peer =~ /^127\.0\.0\.1:(\d+)$/;

		$api_stat{requests}{$port} = $peer_stat->{selected}{total};

		$api_stat{health}{$port}{$_} = $peer_stat->{health}{$_}
			for qw(header_time response_time);
	}

	note(explain({api_stat => \%api_stat}));

	return \%api_stat;
}
