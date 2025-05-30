package Test::API;

# (C) 2025 Web Server LLC

###############################################################################

use warnings;
use strict;

use Exporter qw/import/;
BEGIN {
	our @EXPORT_OK = qw/api_status traverse_api_status/;
}

use Test::More;
use Test::Deep qw/any re hash_each subhashof cmp_details deep_diag/;

use Test::Utils qw/:json :re/;

# describes the maximum set of allowed fields
sub api_status {
	my $t = shift;

	my $with_debug = $t->has_module('debug');

	my $build;
	if ($t->{_configure_args} =~ /--build=(?|'([^']+)'|(\S+))/) {
		$build = $1;
	}

	my $config = $t->read_file('nginx.conf');

	my $string_re = re(qr/^.+$/);

	my $ssl = {
		failed     => $NUM_RE,
		handshaked => $NUM_RE,
		reuses     => $NUM_RE,
		timedout   => $NUM_RE,
	};

	my $data = {
		received => $NUM_RE,
		sent     => $NUM_RE
	};

	my $cache_read = {
		bytes     => $NUM_RE,
		responses => $NUM_RE,
	};

	my $cache = {
		%{ $cache_read },
		bytes_written     => $NUM_RE,
		responses_written => $NUM_RE
	};

	my $peer = {
		backup    => any(JSON::false(), JSON::true()),
		max_conns => $NUM_RE,
		($with_debug ? (refs => $NUM_RE) : ()),
		selected => subhashof({
			current => $NUM_RE,
			total   => $NUM_RE,
			last    => $TIME_RE,
		}),
		server  => $string_re,
		service => $string_re,
		sid     => $string_re,
		state   => $string_re,
		weight  => $NUM_RE,
	};

	my $limit_conns = hash_each({
		exhausted => $NUM_RE,
		passed    => $NUM_RE,
		rejected  => $NUM_RE,
		skipped   => $NUM_RE,
	});

	my $status = {
		angie => {
			address    => $string_re,
			(defined $build) ? (build => $build) : (),
			build_time => $TIME_RE,
			generation => $NUM_RE,
			load_time  => $TIME_RE,
			version    => re(qr/^(\d+\.)?(\d+\.)?(\d+|.+)?$/),
		},
		connections => {
			accepted => $NUM_RE,
			active   => $NUM_RE,
			dropped  => $NUM_RE,
			idle     => $NUM_RE,
		},
		http => subhashof({
			caches => hash_each(
				subhashof({
					bypass   => $cache,
					cold     => any(JSON::false(), JSON::true()),
					expired  => $cache,
					hit      => $cache_read,
					max_size => $NUM_RE,
					miss     => $cache,
					revalidated => $cache_read,
					size     => $NUM_RE,
					stale    => $cache_read,
					updating => $cache_read,
				})
			),
			limit_conns => $limit_conns,
			limit_reqs => hash_each({
				delayed   => $NUM_RE,
				exhausted => $NUM_RE,
				passed    => $NUM_RE,
				rejected  => $NUM_RE,
				skipped   => $NUM_RE,
			}),
			location_zones => hash_each({
				data => $data,
				requests => {
					discarded => $NUM_RE,
					total     => $NUM_RE
				},
				responses => hash_each($NUM_RE),
			}),
			server_zones => hash_each(
				subhashof({
					data => $data,
					responses => hash_each($NUM_RE),
					requests  => {
						discarded  => $NUM_RE,
						processing => $NUM_RE,
						total      => $NUM_RE,
					},
					ssl => $ssl,
				}),
			),
			upstreams => hash_each(
				subhashof({
					keepalive => $NUM_RE,
					peers => hash_each(
						subhashof({
							%{ $peer },
							data   => $data,
							responses => hash_each($NUM_RE),
							health => subhashof({
								downstart     => $TIME_RE,
								downtime      => $NUM_RE,
								fails         => $NUM_RE,
								unavailable   => $NUM_RE,
							}),
						}),
					),
					($with_debug ? (zombies => $NUM_RE)    : ()),
					($with_debug ? (zone    => $string_re) : ()),
				}),
			),
		}),
		resolvers => hash_each({
			queries => {
				name => $NUM_RE,
				srv  => $NUM_RE,
				addr => $NUM_RE,
			},
			responses => {
				format_error   => $NUM_RE,
				not_found      => $NUM_RE,
				other          => $NUM_RE,
				refused        => $NUM_RE,
				server_failure => $NUM_RE,
				success        => $NUM_RE,
				timedout       => $NUM_RE,
				unimplemented  => $NUM_RE,
			},
			sent => {
				a    => $NUM_RE,
				aaaa => $NUM_RE,
				ptr  => $NUM_RE,
				srv  => $NUM_RE
			},
		}),
		slabs => hash_each({
			pages => {
				free => $NUM_RE,
				used => $NUM_RE,
			},
			slots => hash_each({
				fails => $NUM_RE,
				free  => $NUM_RE,
				reqs  => $NUM_RE,
				used  => $NUM_RE,
			}),
		}),
	};

	if ($config =~ /\s+stream\s+{/) {
		$status->{stream} = subhashof({
			limit_conns  => $limit_conns,
			server_zones => hash_each(
				subhashof({
					data => $data,
					connections => {
						discarded  => $NUM_RE,
						processing => $NUM_RE,
						total      => $NUM_RE,
						passed     => $NUM_RE,
					},
					sessions => {
						bad_gateway         => $NUM_RE,
						forbidden           => $NUM_RE,
						internal_error      => $NUM_RE,
						invalid             => $NUM_RE,
						service_unavailable => $NUM_RE,
						success             => $NUM_RE,
					},
					ssl => $ssl,
				}),
			),
			upstreams => hash_each({
				peers => hash_each(
					subhashof({
						%{ $peer },
						data   => $data,
						health => subhashof({
							downstart       => $TIME_RE,
							downtime        => $NUM_RE,
							fails           => $NUM_RE,
							unavailable     => $NUM_RE,
						}),
					}),
				),
				($with_debug ? (zombies => $NUM_RE)    : ()),
				($with_debug ? (zone    => $string_re) : ()),
			}),
		});
	}

	return $status;
}

sub traverse_api_status {
	my ($uri, $expected, %extra) = @_;

	my $api_status = get_json($uri, %extra);
	debug(explain($api_status));

	my ($ok, $stack) = cmp_details($api_status, $expected);
	unless ($ok) {
		diag("WARNING: GET $uri not OK");
		return 0, deep_diag($stack);
	}
	debug("GET $uri OK");

	(my $uri_short = $uri) =~ s/auto-generated-api/status/;

	my $got = put_json($uri, {}, 0, %extra);
	my $exp = {
		h => re('405 Method Not Allowed'),
		j => {
			'description' => 'The PUT method is not allowed for the'
				. ' requested API entity "' . $uri_short . '".',
			'error' => 'MethodNotAllowed'
		}
	};
	($ok, $stack) = cmp_details($got, $exp);

	unless ($ok) {
		diag("PUT $uri not OK");
		diag(explain({got => $got, expected => $exp}));
		return 0, deep_diag($stack);
	}
	debug("PUT $uri OK");

	$got = delete_json($uri, %extra);
	$exp = {
		h => re('405 Method Not Allowed'),
		j => {
			'description' => 'The DELETE method is not allowed for the'
				. ' requested API entity "' . $uri_short . '".',
			'error' => 'MethodNotAllowed'
		}
	};
	($ok, $stack) = cmp_details($got, $exp);

	unless ($ok) {
		diag("DELETE $uri not OK");
		diag(explain({got => $got, expected => $exp}));
		return 0, deep_diag($stack);
	}
	debug("DELETE $uri OK");

	$got = patch_json($uri, {a => '123'}, 0, %extra);
	$exp = {
		h => re('405 Method Not Allowed'),
		j => {
			'description' => 'The PATCH method is not allowed for the'
				. ' requested API entity "' . $uri_short . '".',
			'error' => 'MethodNotAllowed'
		}
	};

	($ok, $stack) = cmp_details($got, $exp);

	unless ($ok) {
		diag("PATCH $uri not OK");
		diag(explain({got => $got, expected => $exp}));
		return 0, deep_diag($stack);
	}
	debug("PATCH $uri OK");

	return $ok
		unless ref $api_status eq 'HASH';

	if (ref $expected eq 'Test::Deep::SubHash') {
		$expected = $expected->{val};
	}

	foreach my $key (keys %{ $api_status }) {
		next if $key eq 'config_files';

		if ($key =~ /^\//) {
			debug("SKIP uri $uri$key");
			next;
		}

		my $expected_val;
		if (ref $expected eq 'Test::Deep::HashEach') {
			$expected_val = $expected->{val};
		} elsif (ref $expected eq 'HASH') {
			$expected_val = $expected->{$key};
		}

		my ($res, $details)
			= traverse_api_status("${uri}${key}/", $expected_val, %extra);

		return $res, $details
			unless $res;
	}

	return 1;
}

sub debug {
	return unless $ENV{TEST_ANGIE_API_VERBOSE};
	diag(shift);
}

1;
