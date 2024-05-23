#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for max_headers directive, HTTP/2.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        http2 on;
        max_headers 5;

        location / {
            return 204;
        }
    }
}

EOF

$t->try_run('no max_headers')->plan(3);

###############################################################################

like(get('/'), qr/ 204/, 'two headers');
like(get('/', ('Foo: bar') x 3), qr/ 204/, 'five headers');
like(get('/', ('Foo: bar') x 4), qr/ 400/, 'six headers rejected');

###############################################################################

sub get {
	my ($url, @headers) = @_;

	my $s = Test::Nginx::HTTP2->new();
	my $sid = $s->new_stream({
		headers => [
			{ name => ':method', value => 'GET' },
			{ name => ':scheme', value => 'http' },
			{ name => ':path', value => $url },
			{ name => ':authority', value => 'localhost' },
			{ name => 'foo', value => 'bar', mode => 2 },
			{ name => 'foo', value => 'bar', mode => 2 },
			map {
				my ($n, $v) = split /:/;
				{ name => lc $n, value => $v, mode => 2 };
			} @headers
		]
	});

	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

	return join("\n", map { "$_: " . $frame->{headers}->{$_}; }
		keys %{$frame->{headers}});
}

###############################################################################
