#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for api/status.
# TODO: resolver

###############################################################################

use warnings;
use strict;

use Test::Deep qw/cmp_details cmp_deeply deep_diag re hash_each/;
use Test::More;
use JSON;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json put_json delete_json patch_json stream_daemon/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_api rewrite stream/)
	->has(qw/upstream_zone stream_upstream_zone/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache keys_zone=cache_zone:2m;
    limit_conn_zone $binary_remote_addr zone=limit_conn_zone:10m;
    limit_req_zone $binary_remote_addr zone=limit_req_zone:10m rate=1r/s;

    upstream u1 {
        zone z1 256k;
        server 127.0.0.1:8081 sid=s1 max_conns=1;
        server 127.0.0.1:8082 sid=s2 max_conns=2 weight=2 backup;
        keepalive 4;
    }

    server {
        listen 127.0.0.1:8081;
        listen 127.0.0.1:8082;
        return 200 OK;
    }

    server {
        server_name www.example.com;
        listen 127.0.0.1:8080;

        status_zone http_server_zone;
        proxy_cache cache_zone;

        access_log %%TESTDIR%%/access.log combined;

        location / {
            status_zone location_zone;
            limit_conn limit_conn_zone 1;
            limit_req zone=limit_req_zone burst=5;
            proxy_pass http://u1;
        }

        location /status/ {
            api /status/;
            api_config_files on;

            allow 127.0.0.1;
            deny all;
        }
    }
}

stream {
    upstream u2 {
        zone z2 256k;
        server 127.0.0.1:8071 sid=s1 max_conns=1;
        server 127.0.0.1:8072 sid=s2 max_conns=2 weight=2 backup;
    }

    server {
        server_name www.example.com;
        listen 127.0.0.1:8090;
        status_zone stream_server_zone;
        proxy_pass u2;
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8071));
$t->run_daemon(\&stream_daemon, port(8072));

$t->run();

$t->waitforsocket('127.0.0.1:' . port(8071));
$t->waitforsocket('127.0.0.1:' . port(8072));

# to produce some stats
get_json('/status/');
get_json('/status/djfkdfj/');
put_json('/status/djfkdfj/');

my %test_cases = (
	'wrong path' => sub {
		is_deeply(
			get_json('/status/xxx/'),
			{
				description => 'Requested API entity "/status/xxx/" '
					. 'doesn\'t exist.',
				error       => 'PathNotFound'
			},
			'wrong path'
		);
	},

	'/status/' => sub {
		my $t = shift;

		http_get('/');
		stream('127.0.0.1:' . port(8090))->io('....$');

		my $with_debug = $t->has_module('--with-debug');

		my $build;
		if ($t->{_configure_args} =~ /--build=(?|'([^']+)'|(\S+))/) {
			$build = $1;
		}

		my $num_re  = re(qr/^\d+$/);
		my $time_re
			= re(qr/^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}(\.\d{3})?Z$/);

		my $slot = {
			fails => $num_re,
			free  => $num_re,
			reqs  => $num_re,
			used  => $num_re,
		};

		my $zone = {
			pages => {
				used => $num_re,
				free => $num_re,
			},
			slots => hash_each($slot),
		};

		my $status = {
			angie => {
				address => '127.0.0.1',
				config_files => {
					$t->testdir . '/nginx.conf' => $t->read_file('nginx.conf'),
				},
				generation => 1,
				load_time  => $time_re,
				version    => re(qr/^(\d+\.)?(\d+\.)?(\d+|.+)?$/),
				(defined $build) ? (build => $build) : (),
				build_time => $time_re,
			},
			connections => {
				accepted => $num_re,
				active   => $num_re,
				dropped  => 0,
				idle     => 0,
			},
			slabs => {
				limit_conn_zone => $zone,
				cache_zone      => $zone,
				limit_req_zone  => $zone,
				z1              => $zone,
				z2              => $zone,
			},
			http => {
				caches => {
					cache_zone => {
						bypass => {
							bytes             => 0,
							bytes_written     => 0,
							responses         => 0,
							responses_written => 0,
						},
						cold    => JSON::true(),
						expired => {
							bytes             => 0,
							bytes_written     => 0,
							responses         => 0,
							responses_written => 0,
						},
						hit => {
							bytes     => 0,
							responses => 0,
						},
						miss => {
							bytes             => 2,
							bytes_written     => 0,
							responses         => 1,
							responses_written => 0,
						},
						revalidated => {
							bytes     => 0,
							responses => 0,
						},
						size  => 0,
						stale => {
							bytes     => 0,
							responses => 0,
						},
						updating => {
							bytes     => 0,
							responses => 0,
						},
					},
				},
				limit_conns => {
					limit_conn_zone => {
						exhausted => 0,
						passed    => 1,
						rejected  => 0,
						skipped   => 0,
					},
				},
				limit_reqs => {
					limit_req_zone => {
						delayed   => 0,
						exhausted => 0,
						passed    => 1,
						rejected  => 0,
						skipped   => 0,
					},
				},
				location_zones => {
					location_zone => {
						data => {
							received => 32,
							sent     => 144,
						},
						requests => {
							discarded => 0,
							total     => 1,
						},
						responses => {
							200 => 1,
						},
					},
				},
				server_zones => {
					http_server_zone => {
						data => {
							received => $num_re,
							sent     => $num_re,
						},
						requests => {
							discarded  => 0,
							processing => $num_re,
							total      => $num_re,
						},
						responses => {
							200 => $num_re,
							404 => $num_re,
							405 => $num_re,
						},
					},
				},
				upstreams => {
					u1 => {
						keepalive => 0,
						peers     => {
							'127.0.0.1:' . port(8081) => {
								backup => JSON::false(),
								data   => {
									received => 144,
									sent     => 47,
								},
								health => {
									downtime => 0,
									fails    => 0,
									unavailable => 0,
								},
								max_conns => 1,
								($with_debug ? (refs => 0) : ()),
								responses => {
									200 => $num_re,
								},
								selected  => {
									current => 0,
									total   => 1,
									last    => $time_re,
								},
								server => '127.0.0.1:' . port(8081),
								sid    => 's1',
								state  => 'up',
								weight => 1
							},
							'127.0.0.1:' . port(8082) => {
								backup => JSON::true(),
								data   => {
									received => 0,
									sent     => 0,
								},
								health => {
									downtime => 0,
									fails    => 0,
									unavailable => 0,
								},
								max_conns => 2,
								($with_debug ? (refs => 0) : ()),
								responses => {},
								selected  => {
									current => 0,
									total   => 0,
								},
								server => '127.0.0.1:' . port(8082),
								sid    => 's2',
								state  => 'up',
								weight => 2,
							},
						},
						($with_debug ? (zombies => 0)    : ()),
						($with_debug ? (zone    => 'z1') : ()),
					},
				},
			},
			resolvers => {},
			stream => {
				limit_conns => {},
				server_zones => {
					stream_server_zone => {
						data => {
							received => 5,
							sent     => length(port(8071)),
						},
						connections => {
							discarded  => 0,
							processing => 0,
							total      => 1,
							passed     => 0,
						},
						sessions => {
							bad_gateway         => 0,
							forbidden           => 0,
							internal_error      => 0,
							invalid             => 0,
							service_unavailable => 0,
							success             => 1,
						},
					},
				},
				upstreams => {
					u2 => {
						peers => {
							'127.0.0.1:' . port(8071) => {
								backup => JSON::false(),
								data   => {
									received => length(port(8071)),
									sent     => 5,
								},
								health => {
									downtime => 0,
									fails    => 0,
									unavailable => 0,
								},
								max_conns => 1,
								($with_debug ? (refs => 0) : ()),
								selected  => {
									current => 0,
									total   => 1,
									last    => $time_re,
								},
								server => '127.0.0.1:' . port(8071),
								sid    => 's1',
								state  => 'up',
								weight => 1
							},
							'127.0.0.1:' . port(8072) => {
								backup => JSON::true(),
								data   => {
									received => 0,
									sent     => 0,
								},
								health => {
									downtime => 0,
									fails    => 0,
									unavailable => 0,
								},
								max_conns => 2,
								($with_debug ? (refs => 0) : ()),
								selected  => {
									current => 0,
									total   => 0
								},
								server => '127.0.0.1:' . port(8072),
								sid    => 's2',
								state  => 'up',
								weight => 2,
							},
						},
						($with_debug ? (zombies => 0)    : ()),
						($with_debug ? (zone    => 'z2') : ()),
					},
				},
			},
		};

		test_api('/status/', $status);
	},
);

$t->plan(scalar keys %test_cases);

$t->run_tests(\%test_cases);

###############################################################################

sub test_api {
	my ($uri, $expected) = @_;

	my $api_status = get_json($uri);
	note(explain($api_status));

	my ($ok, $stack) = cmp_details($api_status, $expected);

	unless ($ok) {
		my $details = deep_diag($stack);
		diag("WARNING: GET $uri not OK:\n" . $details);

		TODO: {
			local $TODO = 'Extra keys in API response'
				if $details && $details =~ /\s+Extra:/
					&& $details !~ /\s+Missing:/;

			Test::More::ok($ok, 'GET $uri OK');
		}
	}

	cmp_deeply(
		put_json($uri, {}),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The PUT method is not allowed for the'
					. ' requested API entity "' . $uri . '".',
				'error' => 'MethodNotAllowed'
			}
		},
		"PUT $uri error OK"
	);

	cmp_deeply(
		delete_json($uri),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The DELETE method is not allowed for the'
					. ' requested API entity "' . $uri . '".',
				'error' => 'MethodNotAllowed'
			}
		},
		"DELETE $uri error OK"
	);

	cmp_deeply(
		patch_json($uri, {a => '123'}),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The PATCH method is not allowed for the'
					. ' requested API entity "' . $uri . '".',
				'error' => 'MethodNotAllowed'
			}
		},
		"PATCH $uri error OK"
	);
}

