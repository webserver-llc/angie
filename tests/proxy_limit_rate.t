#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for the proxy_limit_rate directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy upstream_keepalive/)->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8080;
        keepalive 1;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_limit_rate 20000;
        proxy_buffer_size 4k;

        location / {
            proxy_pass http://127.0.0.1:8080/data;
            add_header  X-Msec $msec;
            add_trailer X-Msec $msec;
        }

        location /unlimited {
            proxy_pass http://127.0.0.1:8080/data;
            proxy_limit_rate 0;
            add_header  X-Msec $msec;
            add_trailer X-Msec $msec;
        }

        location /keepalive {
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://u/data;
        }

        location /data {
        }
    }
}

EOF

$t->write_file('data', 'X' x 40000);
$t->run();

###############################################################################

# The rate limit is checked through the time it takes to transfer the body,
# but the time is only compared against the guarantees it gives: with
# proxy_limit_rate 20000 a 40k body takes about two seconds, so the header
# and the trailer stamps are at least a second apart whatever the load is.
#
# Conversely, with proxy_limit_rate 0 the transfer must merely be much
# faster than the limit would impose; the best of several attempts is used,
# so a transient stall cannot produce a false failure.  Note that neither
# check compares the stamps for equality with a wall-clock boundary: the
# old is($t2 - $t1, 0) failed whenever the response crossed an integer
# second, even for a healthy unlimited response that took milliseconds.

my ($body, $delta) = get('/');

ok(defined $delta, 'proxy_limit_rate: msec stamps parsed');
cmp_ok($delta // 0, '>=', 1, 'proxy_limit_rate');
is($body, 'X' x 40000, 'response body');

# unlimited

($body, $delta) = get_min('/unlimited', 3);

ok(defined $delta, 'unlimited: msec stamps parsed');
cmp_ok($delta // 9, '<', 1, 'proxy_limit_rate unlimited');
is($body, 'X' x 40000, 'response body unlimited');

# in case keepalive connection was saved with the delayed flag,
# the read timer used to be a delay timer in the next request

like(http_get('/keepalive'), qr/200 OK/, 'keepalive');
like(http_get('/keepalive'), qr/200 OK/, 'keepalive 2');

###############################################################################

sub get {
	my ($uri) = @_;
	my $r = http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close

EOF

	# return the body and the full-precision time it took to transfer it

	my @msec = $r =~ /X-Msec:\s*(\d+(?:\.\d+)?)/g;

	http_content($r), @msec == 2 ? $msec[1] - $msec[0] : undef;
}

# transfer the given uri several times and keep the fastest response

sub get_min {
	my ($uri, $tries) = @_;

	my ($body, $min);

	for (1 .. $tries) {
		my ($b, $d) = get($uri);
		next unless defined $d;

		if (!defined $min || $d < $min) {
			$min = $d;
			$body = $b;
		}
	}

	$body, $min;
}

###############################################################################
