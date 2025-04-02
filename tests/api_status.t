#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for api/status.
# TODO: resolver

###############################################################################

use warnings;
use strict;

use Test::Deep qw/cmp_details cmp_deeply deep_diag re hash_each superhashof/;
use Test::More;
use JSON;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json put_json delete_json patch_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_api stream/)
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
        server 127.0.0.1:%%PORT_8081%% sid=s1 max_conns=1;
        server 127.0.0.1:%%PORT_8082%% sid=s2 max_conns=2 weight=2;
        keepalive 4;
    }

    server {
        server_name www.example.com;
        listen 127.0.0.1:8080;

        status_zone http_server_zone;
        proxy_cache cache_zone;

        access_log %%TESTDIR%%/access.log combined;

        location / {
            root /usr/share/angie/html;
            status_zone location_zone;
            limit_conn limit_conn_zone 1;
            limit_req zone=limit_req_zone burst=5;
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
        server 127.0.0.1:%%PORT_8081%% sid=s1 max_conns=1;
        server 127.0.0.1:%%PORT_8082%% sid=s2 max_conns=2 weight=2;
    }

    server {
        server_name www.example.com;
        listen 127.0.0.1:8090;
        status_zone http_server_zone;
        proxy_pass u2;
    }
}

EOF

$t->run();

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

		my $status = superhashof({
			angie => superhashof({
				address => '127.0.0.1',
				config_files => {
					$t->testdir . '/nginx.conf' => $t->read_file('nginx.conf'),
				},
				generation => $num_re,
				load_time  => $time_re,
				version    => re(qr/^(\d+\.)?(\d+\.)?(\d+|.+)?$/),
				(defined $build) ? (build => $build) : (),
				build_time => $time_re,
			}),
			connections => superhashof({
				accepted => $num_re,
				active   => $num_re,
				dropped  => $num_re,
				idle     => $num_re,
			}),
			slabs => superhashof({
				limit_conn_zone => $zone,
				cache_zone      => $zone,
				limit_req_zone  => $zone,
				z1              => $zone,
				z2              => $zone,
			}),
			http => superhashof({
				caches => superhashof({
					cache_zone => superhashof({
						bypass => superhashof({
							bytes             => $num_re,
							bytes_written     => $num_re,
							responses         => $num_re,
							responses_written => $num_re
						}),
						cold    => JSON::true(),
						expired => superhashof({
							bytes             => $num_re,
							bytes_written     => $num_re,
							responses         => $num_re,
							responses_written => $num_re
						}),
						hit => superhashof({
							bytes     => $num_re,
							responses => $num_re
						}),
						miss => superhashof({
							bytes             => $num_re,
							bytes_written     => $num_re,
							responses         => $num_re,
							responses_written => $num_re
						}),
						revalidated => superhashof({
							bytes     => $num_re,
							responses => $num_re
						}),
						size  => $num_re,
						stale => superhashof({
							bytes     => $num_re,
							responses => $num_re
						}),
						updating => superhashof({
							bytes     => $num_re,
							responses => $num_re
						}),
					}),
				}),
				limit_conns => superhashof({
					limit_conn_zone => superhashof({
						exhausted => $num_re,
						passed    => $num_re,
						rejected  => $num_re,
						skipped   => $num_re
					}),
				}),
				limit_reqs => superhashof({
					limit_req_zone => superhashof({
						delayed   => $num_re,
						exhausted => $num_re,
						passed    => $num_re,
						rejected  => $num_re,
						skipped   => $num_re,
					}),
				}),
				location_zones => superhashof({
					location_zone => superhashof({
						data => superhashof({
							received => $num_re,
							sent     => $num_re
						}),
						requests => superhashof({
							discarded => $num_re,
							total     => $num_re
						}),
						responses => superhashof({}),
					}),
				}),
				server_zones => superhashof({
					http_server_zone => superhashof({
						data => superhashof({
							received => $num_re,
							sent     => $num_re,
						}),
						requests => superhashof({
							discarded  => $num_re,
							processing => $num_re,
							total      => $num_re,
						}),
						responses => superhashof({
							200 => $num_re,
							404 => $num_re,
							405 => $num_re,
						}),
					}),
				}),
				upstreams => {
					u1 => superhashof({
						keepalive => $num_re,
						peers     => {
							'127.0.0.1:' . port(8081) => superhashof({
								backup => JSON::false(),
								data   => superhashof({
									received => $num_re,
									sent     => $num_re,
								}),
								health => superhashof({
									downtime => $num_re,
									fails    => $num_re,
									unavailable => $num_re,
								}),
								max_conns => 1,
								($with_debug ? (refs => $num_re) : ()),
								responses => superhashof({}),
								selected  => superhashof({
									current => $num_re,
									total   => $num_re,
								}),
								server => '127.0.0.1:' . port(8081),
								sid    => 's1',
								state  => 'up',
								weight => 1
							}),
							'127.0.0.1:' . port(8082) => superhashof({
								backup => JSON::false(),
								data   => superhashof({
									received => $num_re,
									sent     => $num_re,
								}),
								health => superhashof({
									downtime => $num_re,
									fails    => $num_re,
									unavailable => $num_re,
								}),
								max_conns => 2,
								($with_debug ? (refs => $num_re) : ()),
								responses => superhashof({}),
								selected  => superhashof({
									current => $num_re,
									total   => 0
								}),
								server => '127.0.0.1:' . port(8082),
								sid    => 's2',
								state  => 'up',
								weight => 2,
							}),
						},
						($with_debug ? (zombies => $num_re) : ()),
						($with_debug ? (zone    => 'z1')    : ()),
					}),
				},
			}),
			resolvers => superhashof({}),
			stream => superhashof({
				limit_conns => superhashof({}),
				server_zones => superhashof({
					http_server_zone => superhashof({
						data => superhashof({
							received => $num_re,
							sent     => $num_re,
						}),
						connections => superhashof({
							discarded  => $num_re,
							processing => $num_re,
							total      => $num_re,
							passed     => $num_re,
						}),
						sessions => superhashof({
							bad_gateway         => $num_re,
							forbidden           => $num_re,
							internal_error      => $num_re,
							invalid             => $num_re,
							service_unavailable => $num_re,
							success             => $num_re,
						}),
					}),
				}),
				upstreams => {
					u2 => {
						peers => {
							'127.0.0.1:' . port(8081) => superhashof({
								backup => JSON::false(),
								data   => superhashof({
									received => $num_re,
									sent     => $num_re,
								}),
								health => superhashof({
									downtime => $num_re,
									fails    => $num_re,
									unavailable => $num_re,
								}),
								max_conns => 1,
								($with_debug ? (refs => $num_re) : ()),
								selected  => superhashof({
									current => $num_re,
									total   => $num_re,
								}),
								server => '127.0.0.1:' . port(8081),
								sid    => 's1',
								state  => 'up',
								weight => 1
							}),
							'127.0.0.1:' . port(8082) => superhashof({
								backup => JSON::false(),
								data   => superhashof({
									received => $num_re,
									sent     => $num_re,
								}),
								health => superhashof({
									downtime => $num_re,
									fails    => $num_re,
									unavailable => $num_re,
								}),
								max_conns => 2,
								($with_debug ? (refs => $num_re) : ()),
								selected  => superhashof({
									current => $num_re,
									total   => 0
								}),
								server => '127.0.0.1:' . port(8082),
								sid    => 's2',
								state  => 'up',
								weight => 2,
							}),
						},
						($with_debug ? (zombies => $num_re) : ()),
						($with_debug ? (zone    => 'z2')    : ()),
					},
				},
			}),
		});

		traverse_api('/status/', $status);
	},
);

$t->plan(scalar keys %test_cases);

$t->run_tests(\%test_cases);

###############################################################################

sub traverse_api {
	my ($uri, $expected) = @_;

	my $get_res = get_json($uri);

	cmp_deeply($get_res, $expected, "GET $uri OK")
		or return;

	if (ref $expected eq 'Test::Deep::SuperHash') {
		$expected = $expected->{val};

		my ($ok, $stack) = cmp_details($get_res, $expected);
		diag("WARNING: GET $uri: " . deep_diag($stack))
			unless $ok;
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
	)
		or return;

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
	)
		or return;

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
	)
		or return;

	if (ref $expected eq 'Test::Deep::HashEach') {
		for my $key (keys %{ $get_res }) {
			traverse_api($uri . "$key/", $expected->{val})
				or return;
		}
	} elsif (ref $expected eq 'HASH') {
		while (my ($key, $value) = each %{ $expected }) {
			next if $key eq 'config_files';
			traverse_api($uri . "$key/", $value)
				or return;
		}
	}

	return 1;
}

