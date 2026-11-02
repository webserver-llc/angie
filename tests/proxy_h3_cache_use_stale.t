#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) 2023 Web Server LLC

# Tests for http proxy cache, proxy_cache_use_stale.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite ssi/)
	->has_daemon("openssl");

$t->has(qw/http_v3/);
$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2  keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /ssi.html {
            ssi on;
            sendfile_max_chunk  4k;
        }

        location /escape {
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;
            proxy_http_version  3;
            proxy_cache   NAME;
            proxy_cache_background_update  on;
            add_header X-Cache-Status $upstream_cache_status;
        }

        location / {
            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;
            proxy_http_version  3;

            proxy_cache   NAME;

            proxy_cache_key  $uri;

            proxy_cache_revalidate  on;

            proxy_cache_background_update  on;

            add_header X-Cache-Status $upstream_cache_status;

            location /t4.html {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%/t4u.html;
                proxy_http_version  3;

                proxy_cache_revalidate  off;
            }

            location /t5.html {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%/t5u.html;
                proxy_http_version  3;

                proxy_cache_background_update  off;
            }

            location ~ /(reg)(?P<name>exp).html {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%/$1$name.html;
                proxy_http_version  3;

                proxy_cache_background_update  on;
            }

            location /updating/ {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%/;
                proxy_http_version  3;

                proxy_cache_use_stale  updating;
            }

            location /t7.html {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%;
                proxy_http_version  3;

                sendfile_max_chunk  4k;
            }

            location /t8.html {
                proxy_pass    https://127.0.0.1:%%PORT_8999_UDP%%/t8u.html;
                proxy_http_version  3;

                proxy_cache_valid  1s;
            }

            if ($arg_if) {
                # nothing
            }
        }
    }
    server {
        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        add_header Cache-Control $http_x_cache_control;

        # deterministic hold for background updates: the request-side "?lim=1"
        # slows the response down to 1k/s, so an update of an N-byte body stays
        # in flight for at least N seconds whatever the system load is

        if ($arg_lim) {
            set $limit_rate 1k;
        }

        if ($arg_e) {
            return 500;
        }

        location / { }

        location /t9.html {
            add_header Cache-Control "max-age=1, stale-while-revalidate=600";
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->write_file('swr_cached.html', 'SEE-THIS');
$t->write_file('sie_ignore1.html', 'SEE-THIS');
$t->write_file('sie_ignore2.html', 'SEE-THIS');
$t->write_file('sie_upd.html', 'SEE-THIS');
$t->write_file('sie_reval.html', 'SEE-THIS');
$t->write_file('swr1.html', 'SEE-THIS');
$t->write_file('t4u.html', 'SEE-THIS');
$t->write_file('t5u.html', 'SEE-THIS');
$t->write_file('t6.html', 'SEE-THIS');
$t->write_file('upd1.html', 'SEE-THIS');
$t->write_file('t8u.html', 'SEE-THIS');
$t->write_file('swr_again.html', 'SEE-THIS');
$t->write_file('swr_cess.html', 'SEE-THIS');
$t->write_file('sie_cess.html', 'SEE-THIS');
$t->write_file('swr_ovr.html', 'SEE-THIS');
$t->write_file('t7.html', 'SEE-THIS' x 1024);
$t->write_file('t9.html', 'SEE-THIS' x 1024);
$t->write_file('ssi.html', 'xxx <!--#include virtual="/t9.html" --> xxx');
$t->write_file('if.html', 'SEE-THIS');
$t->write_file('escape.html', 'SEE-THIS');
$t->write_file('regexp.html', 'SEE-THIS');

$t->run()->plan(34);

###############################################################################

# The test avoids wall-clock assumptions:
#
# - every cache entry that must be *stale* when checked is created with
#   max-age=1 and a very long stale-while-revalidate/stale-if-error window,
#   so "sleep 2" only provides a lower bound on the entry age and no check
#   can ever fall outside its window;
#
# - entries that must be *past* their window ("ceased") use short windows
#   and are checked after a guaranteed sleep longer than the window; extra
#   delay only moves them further past it;
#
# - states that exist only transiently (UPDATING, HIT after an update) are
#   observed with poll_until() which waits for the condition instead of
#   assuming when it happens;
#
# - background updates are held open with "?lim=1" (limit_rate 1k on the
#   upstream side) and a large body, which gives a load-independent lower
#   bound on how long the update stays in flight.

my @keep;
my %kept;

###############################################################################

like(get('/t.html', 'max-age=600, stale-if-error=600'), qr/MISS/,
	'stale-if-error');
like(http_get('/t.html?e=1'), qr/HIT/, 's-i-e - cached');

like(get('/swr_cached.html', 'max-age=600, stale-while-revalidate=600'),
	qr/MISS/, 'stale-while-revalidate');
like(http_get('/swr_cached.html'), qr/HIT/, 's-w-r - cached');

# entries checked later as stale; age >= 2s at check time, window = 600s

get('/sie_ignore1.html', 'max-age=1, stale-if-error=600');
get('/sie_ignore2.html', 'max-age=1, stale-if-error=600');
get('/updating/sie_upd.html', 'max-age=1, stale-if-error=600');
get('/sie_reval.html', 'max-age=1, stale-if-error=600');
get('/swr1.html', 'max-age=1, stale-while-revalidate=600');
get('/t4.html', 'max-age=1, stale-while-revalidate=600');
get('/t5.html', 'max-age=1, stale-while-revalidate=600');
get('/regexp.html', 'max-age=1, stale-while-revalidate=600');
get('/t6.html', 'max-age=1, stale-while-revalidate=600');
get('/updating/upd1.html', 'max-age=1');
get('/t8.html', 'stale-while-revalidate=600');
get('/t7.html', 'max-age=1, stale-while-revalidate=600');
http_get('/ssi.html');
get('/escape.htm%6C', 'max-age=1, stale-while-revalidate=600');
get('/if.html', 'max-age=1, stale-while-revalidate=600');
get('/swr_again.html', 'max-age=1, stale-while-revalidate=600');

sleep 2;

# stale 5xx response is ignored since 1.19.3,
# "proxy_cache_use_stale updating;" allows to get it still

like(http_get('/sie_ignore1.html?e=1'), qr/ 500 /, 's-i-e - stale 5xx ignore');
like(http_get('/sie_ignore2.html?e=1'), qr/ 500 /,
	's-i-e - stale 5xx ignore 2');
like(http_get('/updating/sie_upd.html'), qr/STALE/,
	's-i-e - stale 5xx updating');
like(http_get('/sie_reval.html'), qr/REVALIDATED/, 's-i-e - revalidated');

like(http_get('/swr1.html?e=1'), qr/STALE/, 's-w-r - revalidate error');

$t->write_file('swr1.html', 'SEE-THAT');

my $s = get('/swr1.html', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 's-w-r - stale while revalidate');
like(poll_until(sub { http_get('/swr1.html') }, qr/HIT/), qr/HIT/,
	's-w-r - revalidated');

$t->write_file('t4u.html', 'SEE-THAT');

$s = get('/t4.html', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 's-w-r - unconditional revalidate');
like(poll_until(sub { http_get('/t4.html') }, qr/HIT/), qr/HIT/,
	's-w-r - unconditional revalidated');

like(http_get('/t5.html?e=1'), qr/ 500 /,
	's-w-r - foreground revalidate error');
like(http_get('/t5.html'), qr/REVALIDATED/, 's-w-r - foreground revalidated');

# proxy_pass to regular expression with named and positional captures

$t->write_file('regexp.html', 'SEE-THAT');

$s = get('/regexp.html', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 's-w-r - regexp background update');
like(poll_until(sub { http_get('/regexp.html') }, qr/HIT/), qr/HIT/,
	's-w-r - regexp revalidated');

# UPDATING while s-w-r: the update of the 10k body below is throttled to
# 1k/s upstream, so it is guaranteed to stay in flight for ~10 seconds

$t->write_file('t6.html', 'SEE-THAT' x 1280);

$s = get('/t6.html?lim=1', 'max-age=600', start => 1);
my $r = read_resp($s);
my $u = poll_until(sub { http_get('/t6.html') }, qr/UPDATING/, 25);
like($u, qr/UPDATING.*SEE-THIS/s, 's-w-r - updating');
like($r, qr/STALE.*SEE-THIS/s, 's-w-r - updating stale');
like(poll_until(sub { http_get('/t6.html') }, qr/HIT/, 150),
	qr/HIT.*SEE-THAT/s, 's-w-r - updating revalidated');

# stale-while-revalidate with proxy_cache_use_stale updating

$t->write_file('upd1.html', 'SEE-THAT');

$s = get('/updating/upd1.html', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 's-w-r - use_stale updating stale');
like(poll_until(sub { http_get('/updating/upd1.html') }, qr/HIT/), qr/HIT/,
	's-w-r - use_stale updating revalidated');

# stale-while-revalidate with proxy_cache_valid

$t->write_file('t8u.html', 'SEE-THAT');

$s = get('/t8.html', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 's-w-r - proxy_cache_valid revalidate');
like(poll_until(sub { http_get('/t8.html') }, qr/HIT/), qr/HIT/,
	's-w-r - proxy_cache_valid revalidated');

# the entry is revalidated (fresh for max-age=1), goes stale again, and
# stale-while-revalidate still applies

$t->write_file('swr_again.html', 'SEE-THAT');

$s = get('/swr_again.html', 'max-age=1, stale-while-revalidate=600',
	start => 1);
read_resp($s);

# wait for the update to land first: its max-age=1 restarts the freshness
# clock whenever the update completes, so the sleep below is a lower bound
# on the age of the *updated* entry only after this poll returns

poll_until(sub { http_get('/swr_again.html') }, qr/SEE-THAT/);

sleep 2;

like(http_get('/swr_again.html?e=1'), qr/STALE/,
	's-w-r - stale after revalidate');

# windows that must be already closed are 1s wide and checked after 3s:
# extra delay only moves the checks further past them

get('/swr_cess.html', 'max-age=1, stale-while-revalidate=1');
get('/sie_cess.html', 'max-age=1, stale-if-error=1');
get('/updating/swr_ovr.html', 'max-age=1, stale-while-revalidate=1');

sleep 3;

like(http_get('/swr_cess.html?e=1'), qr/ 500 /, 's-w-r - ceased');
like(http_get('/sie_cess.html?e=1'), qr/ 500 /, 's-i-e - ceased');
like(http_get('/updating/swr_ovr.html'), qr/STALE/,
	's-w-r - overriden with use_stale updating');

# stale response not blocked by background update.
# before 1.13.1, if stale response was not sent in one pass, its remaining
# part was blocked and not sent until background update has been finished.
# the update of the 40k body is throttled to 1k/s (~40s in flight), so a
# response blocked behind it cannot possibly arrive within the deadline

$t->write_file('t7.html', 'SEE-THAT' x 5120);

$s = get('/t7.html?lim=1', 'max-age=600', start => 1);
$r = read_resp($s, body => 8192, deadline => 15);
like($r, qr/STALE.*^(SEE-THIS){1024}$/ms,
	's-w-r - stale response not blocked');

$t->write_file('t9.html', 'SEE-THAT' x 5120);
$t->write_file('ssi.html',
	'xxx <!--#include virtual="/t9.html?lim=1" --> xxx');

# HTTP/1.0 is used to get the response without chunked framing, since the
# SSI output length is not known in advance

$s = get10('/ssi.html', start => 1);
$r = read_resp($s, body => 8200, deadline => 15);
like($r, qr/^xxx (SEE-THIS){1024} xxx$/ms,
	's-w-r - not blocked in subrequest');

# "aio_write" is used to produce "open socket ... left in connection" alerts.
$t->skip_errors_check('alert', 'open socket #\d+ left in connection')
	if $t->read_file('nginx.conf') =~ /aio_write on/
		and $t->read_file('nginx.conf') =~ /aio threads/ and $^O eq 'freebsd';

# due to the missing content_handler inheritance in a cloned subrequest,
# this used to access a static file in the update request

$t->write_file('if.html', 'SEE-THAT');

$s = get('/if.html?if=1', 'max-age=600', start => 1);
like(read_resp($s), qr/STALE/, 'background update in if');
like(poll_until(sub { http_get('/if.html?if=1') }, qr/HIT/), qr/HIT/,
	'background update in if - updated');

# ticket #1430, uri escaping in cloned subrequests

$t->write_file('escape.html', 'SEE-THAT');

$s = get('/escape.htm%6C', 'max-age=600', start => 1);
read_resp($s);
like(poll_until(sub { http_get('/escape.htm%6C') }, qr/HIT/), qr/HIT/,
	'escaped after escaped');

like(http_get('/escape.html'), qr/MISS/, 'unescaped after escaped');

close $_ for grep { defined fileno($_) } @keep;

###############################################################################

sub get {
	my ($url, $extra, %extra) = @_;
	return http(<<EOF, %extra);
GET $url HTTP/1.1
Host: localhost
Connection: close
X-Cache-Control: $extra

EOF
}

# HTTP/1.0 request: response is EOF-framed, no chunked encoding

sub get10 {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
GET $url HTTP/1.0
Host: localhost

EOF
}

# read_resp($socket, body => $bytes, deadline => $seconds)
#
# Reads a response from the socket until the expected number of body bytes
# has arrived (the count is taken from Content-Length when not given) or the
# deadline expires.  Never waits for connection close: background updates
# postpone it, and the whole point is not to depend on that.

sub read_resp {
	my ($s, %o) = @_;

	# hold the socket: background updates postpone connection close, and
	# closing early may abort the update that later checks wait for

	push @keep, $s unless $kept{fileno($s)}++;

	my $deadline = time + ($o{deadline} || 15);
	my $want = $o{body};
	my $data = '';

	while (1) {
		if ($data =~ /\r\n\r\n/) {
			my ($head, $body) = split /\r\n\r\n/, $data, 2;

			if (!defined $want and $head =~ /Content-Length:\s*(\d+)/i) {
				$want = $1;
			}

			last if defined $want and length($body) >= $want;
		}

		my $left = $deadline - time;
		last if $left <= 0;

		last unless IO::Select->new($s)->can_read($left);

		my $n = $s->sysread(my $buf, 65536);
		last unless $n;

		log_in($buf);
		$data .= $buf;
	}

	return $data;
}

# poll_until($request_generator, $regexp, $tries, $gap)
#
# Re-runs the request until the response matches, adapting to however long
# the expected state takes to appear under load.  Returns the last response.

sub poll_until {
	my ($gen, $re, $tries, $gap) = @_;
	$tries ||= 60;
	$gap ||= 0.2;

	my $r;

	for (1 .. $tries) {
		$r = $gen->();
		return $r if defined $r and $r =~ $re;
		select undef, undef, undef, $gap;
	}

	return $r;
}

###############################################################################
