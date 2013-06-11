#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http proxy and prematurely closed connections.  Incomplete
# responses shouldn't loose information about their incompleteness.

# In particular, incomplete responses:
#
# - shouldn't be cached
#
# - if a response is sent using chunked transfer encoding, 
#   final chunk shouldn't be sent

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http proxy cache sub/)->plan(4)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=one:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            sub_filter foo bar;
            sub_filter_types *;
            proxy_pass http://127.0.0.1:8081;
        }

        location /cache/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_cache one;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:8081');

###############################################################################

my ($r, $n);

$r = http_get('/cache/length');
$r =~ m/unfinished (\d+)/; $n = $1 + 1;
like(http_get('/cache/length'), qr/unfinished $n/, 'unfinished not cached');

TODO: {
local $TODO = 'not yet';

# chunked encoding has enough information to don't cache a response,
# much like with Content-Length available

$r = http_get('/cache/chunked');
$r =~ m/unfinished (\d+)/; $n = $1 + 1;
like(http_get('/cache/chunked'), qr/unfinished $n/, 'unfinished chunked');

}

TODO: {
local $TODO = 'not yet';

# make sure there is no final chunk in normal responses

like(http_get_11('/length'), qr/unfinished(?!.*\x0d\x0a?0\x0d\x0a?)/s,
	'length no final chunk');
like(http_get_11('/chunked'), qr/unfinished(?!.*\x0d\x0a?0\x0d\x0a?)/s,
	'chunked no final chunk');

}

###############################################################################

sub http_get_11 {
	my ($uri) = @_;

	return http(
		"GET $uri HTTP/1.1" . CRLF .
		"Connection: close" . CRLF .
		"Host: localhost" . CRLF . CRLF
	);
}

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:8081',
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my $num = 0;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;
		$num++;

		if ($uri eq '/length') {
			print $client
				"HTTP/1.1 200 OK" . CRLF .
				"Content-Length: 100" . CRLF .
				"Cache-Control: max-age=300" . CRLF .
				"Connection: close" . CRLF .
				CRLF .
				"unfinished $num" . CRLF;

		} elsif ($uri eq '/chunked') {
			print $client
				"HTTP/1.1 200 OK" . CRLF .
				"Transfer-Encoding: chunked" . CRLF .
				"Cache-Control: max-age=300" . CRLF .
				"Connection: close" . CRLF .
				CRLF .
				"ff" . CRLF .
				"unfinished $num" . CRLF;
		}
	}
}

###############################################################################
