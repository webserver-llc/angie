#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with unbuffered request body.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2 qw/ :DEFAULT :frame :io /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2;
        server_name  localhost;

        location / {
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:8081/;
            client_body_buffer_size 1k;
        }
        location /chunked {
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8081/;
            client_body_buffer_size 1k;
        }
    }
}

EOF

$t->run();

my $f = get_body('/chunked');
plan(skip_all => 'no unbuffered request body') unless $f;
$f->{http_end}();

$t->plan(70);

###############################################################################

# unbuffered request body

$f = get_body('/', 'content-length' => 10);
ok($f->{headers}, 'request');
is($f->{upload}('01234', body_more => 1), '01234', 'part');
is($f->{window}, 10, 'part - window');
is($f->{upload}('56789'), '56789', 'part 2');
is($f->{window}, 5, 'part 2 - window');
is($f->{http_end}(), 200, 'response');

$f = get_body('/', 'content-length' => 10);
ok($f->{headers}, 'much');
is($f->{upload}('0123456789', body_more => 1), '0123456789', 'much - part');
is($f->{window}, 10, 'much - part - window');
is($f->{upload}('many'), '', 'much - part 2');
is($f->{window}, 10, 'much - part 2 - window');
is($f->{http_end}(), 400, 'much - response');

$f = get_body('/', 'content-length' => 10);
ok($f->{headers}, 'less');
is($f->{upload}('0123', body_more => 1), '0123', 'less - part');
is($f->{window}, 10, 'less - part - window');
is($f->{upload}('56789'), '', 'less - part 2');
is($f->{window}, 4, 'less - part 2 - window');
is($f->{http_end}(), 400, 'less - response');

$f = get_body('/', 'content-length' => 18);
ok($f->{headers}, 'many');
is($f->{upload}('01234many', body_split => [ 5 ], body_more => 1),
	'01234many', 'many - part');
is($f->{window}, 18, 'many - part - window');
is($f->{upload}('56789many', body_split => [ 5 ]),
	'56789many', 'many - part 2');
is($f->{window}, 9, 'many - part 2 - window');
is($f->{http_end}(), 200, 'many - response');

$f = get_body('/', 'content-length' => 0);
ok($f->{headers}, 'empty');
is($f->{upload}('', body_more => 1), '', 'empty - part');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.9.15');

is($f->{window}, undef, 'empty - part - window');

}

is($f->{upload}(''), '', 'empty - part 2');
is($f->{window}, undef, 'empty - part 2 - window');
is($f->{http_end}(), 200, 'empty - response');

$f = get_body('/', 'content-length' => 1536);
ok($f->{headers}, 'buffer');
is($f->{upload}('0123' x 128, body_more => 1), '0123' x 128,
	'buffer - below');
is($f->{window}, 1024, 'buffer - below - window');
is($f->{upload}('4567' x 128, body_more => 1), '4567' x 128,
	'buffer - equal');
is($f->{window}, 512, 'buffer - equal - window');
is($f->{upload}('89AB' x 128), '89AB' x 128, 'buffer - above');
is($f->{window}, 512, 'buffer - above - window');
is($f->{http_end}(), 200, 'buffer - response');

$f = get_body('/', 'content-length' => 10);
ok($f->{headers}, 'split');
is($f->{upload}('0123456789', split => [ 14 ]), '0123456789', 'split');
is($f->{http_end}(), 200, 'split - response');

# unbuffered request body, chunked transfer-encoding

$f = get_body('/chunked');
ok($f->{headers}, 'chunked');
is($f->{upload}('01234', body_more => 1), '5' . CRLF . '01234' . CRLF,
	'chunked - part');
is($f->{window}, 1024, 'chunked - part - window');
is($f->{upload}('56789'), '5' . CRLF . '56789' . CRLF . '0' . CRLF . CRLF,
	'chunked - part 2');
is($f->{window}, 5, 'chunked - part 2 - window');
is($f->{http_end}(), 200, 'chunked - response');

$f = get_body('/chunked');
ok($f->{headers}, 'chunked buffer');
is($f->{upload}('0123' x 128, body_more => 1),
	'200' . CRLF . '0123' x 128 . CRLF, 'chunked buffer - below');
is($f->{window}, 1024, 'chunked buffer - below - window');
is($f->{upload}('4567' x 128, body_more => 1),
	'200' . CRLF . '4567' x 128 . CRLF, 'chunked buffer - equal');
is($f->{window}, 512, 'chunked buffer - equal - window');
is($f->{upload}('89AB' x 128),
	'200' . CRLF . '89AB' x 128 . CRLF . '0' . CRLF . CRLF,
	'chunked buffer - above');
is($f->{window}, 512, 'chunked buffer - above - window');
is($f->{http_end}(), 200, 'chunked buffer - response');

$f = get_body('/chunked');
ok($f->{headers}, 'chunked many');
is($f->{upload}('01234many', body_split => [ 5 ], body_more => 1),
	'9' . CRLF . '01234many' . CRLF, 'chunked many - part');
is($f->{window}, 1024, 'chunked many - part - window');
is($f->{upload}('56789many', body_split => [ 5 ]),
	'9' . CRLF . '56789many' . CRLF . '0' . CRLF . CRLF,
	'chunked many - part 2');
is($f->{window}, 9, 'chunked many - part 2 - window');
is($f->{http_end}(), 200, 'chunked many - response');

$f = get_body('/chunked');
ok($f->{headers}, 'chunked empty');
is($f->{upload}('', body_more => 1), '', 'chunked empty - part');
is($f->{window}, 1024, 'chunked empty - part - window');
is($f->{upload}(''), '0' . CRLF . CRLF, 'chunked empty - part 2');
is($f->{window}, undef, 'chunked empty - part 2 - window');
is($f->{http_end}(), 200, 'chunked empty - response');

$f = get_body('/chunked');
ok($f->{headers}, 'chunked split');
is($f->{upload}('0123456789', split => [ 14 ]),
	'5' . CRLF . '01234' . CRLF . '5' . CRLF . '56789' . CRLF .
	'0' . CRLF . CRLF, 'chunked split');
is($f->{http_end}(), 200, 'chunked split - response');

###############################################################################

sub get_body {
	my ($url, %extra) = @_;
	my ($server, $client, $f);

	$server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => 8081,
		Listen => 5,
		Timeout => 3,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	my $sess = new_session(8080);
	my $sid = exists $extra{'content-length'}
		? new_stream($sess, { headers => [
			{ name => ':method', value => 'GET' },
			{ name => ':scheme', value => 'http' },
			{ name => ':path', value => $url, },
			{ name => ':authority', value => 'localhost' },
			{ name => 'content-length',
				value => $extra{'content-length'} }],
			body_more => 1 })
		: new_stream($sess, { path => $url, body_more => 1 });

	$client = $server->accept() or return;

	log2c("(new connection $client)");

	$f->{headers} = raw_read($client, '', 1, \&log2i);

	my $chunked = $f->{headers} =~ /chunked/;

	my $body_read = sub {
		my ($s, $buf, $len) = @_;

		for (1 .. 10) {
			$buf = raw_read($s, $buf, length($buf) + 1, \&log2i)
				or return '';

			my $got = 0;
			$got += $chunked ? hex $_ : $_ for $chunked
				? $buf =~ /(\w+)\x0d\x0a?\w+\x0d\x0a?/g
				: length($buf);
			last if $got >= $len;
		}

		return $buf;
	};

	$f->{upload} = sub {
		my ($body, %extra) = @_;

		my $frames = h2_read($sess,
			all => [{ type => 'WINDOW_UPDATE' }]);
		my ($frame) = grep { $_->{type} eq "WINDOW_UPDATE" } @$frames;
		$f->{window} = $frame->{wdelta};

		h2_body($sess, $body, { %extra });

		return $body_read->($client, '', length($body));
	};
	$f->{http_end} = sub {
		$client->write(<<EOF);
HTTP/1.1 200 OK
Connection: close

EOF

		$client->close;

		my $frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
		my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
		return $frame->{headers}->{':status'};
	};
	return $f;
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
