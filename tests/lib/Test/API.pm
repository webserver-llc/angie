package Test::API;

# (C) 2025 Web Server LLC

###############################################################################

use warnings;
use strict;

use parent qw/Exporter/;
use Test::More;
use Test::Deep qw/any re hash_each subhashof ignore cmp_details deep_diag/;

use Test::Utils qw/get_json put_json delete_json patch_json/;

our @EXPORT_OK = qw/api_status traverse_api_status/;

sub api_status {
	my $t = shift;

	my $with_debug = $t->has_module('--with-debug');

	my $build;
	if ($t->{_configure_args} =~ /--build=(?|'([^']+)'|(\S+))/) {
		$build = $1;
	}

	my $num_re  = re(qr/^\d+$/);
	my $time_re = re(qr/^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}(\.\d{3})?Z$/);

	my $ssl = {
		handshaked => $num_re,
		reuses     => $num_re,
		timedout   => $num_re,
		failed     => $num_re,
	};

	my $status = subhashof({
		angie => subhashof({
			address      => ignore(),
			config_files => ignore(),
			generation   => $num_re,
			load_time    => $time_re,
			version      => re(qr/^(\d+\.)?(\d+\.)?(\d+|.+)?$/),
			build_time   => $time_re,
			(defined $build) ? (build => $build) : (),
		}),
		connections => subhashof({
			accepted => $num_re,
			active   => $num_re,
			dropped  => $num_re,
			idle     => $num_re,
		}),
		slabs => hash_each(
			subhashof({
				pages => {
					used => $num_re,
					free => $num_re,
				},
				slots => hash_each({
					fails => $num_re,
					free  => $num_re,
					reqs  => $num_re,
					used  => $num_re,
				}),
			}),
		),
		http  => subhashof({
			caches => hash_each(
				subhashof({
					size     => $num_re,
					max_size => $num_re,
					cold     => JSON::true(),
					hit => subhashof({
						bytes     => $num_re,
						responses => $num_re,
					}),
					stale => subhashof({
						bytes     => $num_re,
						responses => $num_re,
					}),
					updating => subhashof({
						responses => $num_re,
						bytes     => $num_re,
					}),
					revalidated => subhashof({
						responses => $num_re,
						bytes     => $num_re,
					}),
					miss => subhashof({
						bytes             => $num_re,
						bytes_written     => $num_re,
						responses         => $num_re,
						responses_written => $num_re
					}),
					bypass => subhashof({
						bytes             => $num_re,
						bytes_written     => $num_re,
						responses         => $num_re,
						responses_written => $num_re
					}),
					expired => subhashof({
						bytes             => $num_re,
						bytes_written     => $num_re,
						responses         => $num_re,
						responses_written => $num_re
					}),
				}),
			),
			limit_conns => hash_each(
				subhashof({
					exhausted => $num_re,
					passed    => $num_re,
					rejected  => $num_re,
					skipped   => $num_re
				}),
			),
			limit_reqs => hash_each(
				subhashof({
					delayed   => $num_re,
					exhausted => $num_re,
					passed    => $num_re,
					rejected  => $num_re,
					skipped   => $num_re,
				}),
			),
			location_zones => hash_each(
				subhashof({
					data => subhashof({
						received => $num_re,
						sent     => $num_re
					}),
					requests => subhashof({
						discarded => $num_re,
						total     => $num_re
					}),
					responses => hash_each($num_re),
				}),
			),
			server_zones => hash_each(
				subhashof({
					data => subhashof({
						received => $num_re,
						sent     => $num_re,
					}),
					requests => subhashof({
						discarded  => $num_re,
						processing => $num_re,
						total      => $num_re,
					}),
					ssl => $ssl,
					responses => hash_each($num_re),
				}),
			),
			upstreams => hash_each(
				subhashof({
					keepalive => $num_re,
					peers     => hash_each(
						subhashof({
							backup => any(JSON::false(), JSON::true()),
							data   => subhashof({
								received => $num_re,
								sent     => $num_re,
							}),
							health => subhashof({
								downtime    => $num_re,
								fails       => $num_re,
								unavailable => $num_re,
								downstart   => $time_re,
							}),
							max_conns => $num_re,
							($with_debug ? (refs => $num_re) : ()),
							responses => hash_each($num_re),
							selected  => subhashof({
								current => $num_re,
								total   => $num_re,
								last    => $time_re,
							}),
							server  => ignore(),
							service => ignore(),
							sid     => ignore(),
							state   => ignore(),
							weight  => $num_re,
						}),
					),
					($with_debug ? (zombies => $num_re)  : ()),
					($with_debug ? (zone    => ignore()) : ()),
				}),
			),
		}),
		resolvers => hash_each(
			subhashof({
				queries => {
					name => $num_re,
					srv  => $num_re,
					addr => $num_re,
				},
				responses => {
					format_error   => $num_re,
					not_found      => $num_re,
					other          => $num_re,
					refused        => $num_re,
					server_failure => $num_re,
					success        => $num_re,
					timedout       => $num_re,
					unimplemented  => $num_re,
				},
				sent => {
					a    => $num_re,
					aaaa => $num_re,
					ptr  => $num_re,
					srv  => $num_re
				},
			}),
		),
		stream => subhashof({
			limit_conns => hash_each(
				subhashof({
					exhausted => $num_re,
					passed    => $num_re,
					rejected  => $num_re,
					skipped   => $num_re,
				})
			),
			server_zones => hash_each(
				subhashof({
					data => subhashof({
						received => $num_re,
						sent     => $num_re,
					}),
					connections => subhashof({
						discarded  => $num_re,
						processing => $num_re,
						total      => $num_re,
						passed     => $num_re,
					}),
					sessions => subhashof({
						bad_gateway         => $num_re,
						forbidden           => $num_re,
						internal_error      => $num_re,
						invalid             => $num_re,
						service_unavailable => $num_re,
						success             => $num_re,
					}),
					ssl => $ssl,
				}),
			),
			upstreams => hash_each(
				subhashof({
					peers => hash_each(
						subhashof({
							backup => any(JSON::false(), JSON::true()),
							data   => subhashof({
								received => $num_re,
								sent     => $num_re,
							}),
							health => subhashof({
								downtime    => $num_re,
								fails       => $num_re,
								unavailable => $num_re,
								downstart   => $time_re,
							}),
							max_conns => $num_re,
							($with_debug ? (refs => $num_re) : ()),
							selected  => subhashof({
								current => $num_re,
								total   => $num_re,
								last    => $time_re,
							}),
							server  => ignore(),
							service => ignore(),
							sid     => ignore(),
							state   => ignore(),
							weight  => $num_re,
						}),
					),
					($with_debug ? (zombies => $num_re)  : ()),
					($with_debug ? (zone    => ignore()) : ()),
				}),
			),
		}),
	});

	return $status;
}

sub traverse_api_status {
	my ($uri, $expected, %extra) = @_;

	my $api_status = get_json($uri, %extra);
	note(explain($api_status));

	my ($ok, $stack) = cmp_details($api_status, $expected);

	unless ($ok) {
		diag("GET $uri not OK");
		return 0, deep_diag($stack);
	}
	note("GET $uri OK");

	(my $uri_short = $uri) =~ s/auto-generated-api/status/;
	($ok, $stack) = cmp_details(
		put_json($uri, {}, 0, %extra),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The PUT method is not allowed for the'
					. ' requested API entity "' . $uri_short . '".',
				'error' => 'MethodNotAllowed'
			}
		}
	);

	unless ($ok) {
		diag("PUT $uri not OK");
		return 0, deep_diag($stack);
	}
	note("PUT $uri OK");

	($ok, $stack) = cmp_details(
		delete_json($uri, %extra),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The DELETE method is not allowed for the'
					. ' requested API entity "' . $uri_short . '".',
				'error' => 'MethodNotAllowed'
			}
		}
	);

	unless ($ok) {
		diag("DELETE $uri not OK");
		return 0, deep_diag($stack);
	}
	note("DELETE $uri OK");

	($ok, $stack) = cmp_details(
		patch_json($uri, {a => '123'}, 0, %extra),
		{
			h => re('405 Method Not Allowed'),
			j => {
				'description' => 'The PATCH method is not allowed for the'
					. ' requested API entity "' . $uri_short . '".',
				'error' => 'MethodNotAllowed'
			}
		}
	);

	unless ($ok) {
		diag("PATCH $uri not OK");
		return 0, deep_diag($stack);
	}
	note("PATCH $uri OK");

	return $ok
		unless ref $api_status eq 'HASH';

	if (ref $expected eq 'Test::Deep::SubHash') {
		$expected = $expected->{val};
	}

	foreach my $key (keys %{ $api_status }) {
		next if $key eq 'config_files';

		if ($key =~ /^\//) {
			note("SKIP uri $uri$key");
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

1;
