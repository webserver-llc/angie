#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for JSON escaping in error_log
# Various log levels emitted with limit_req_log_level.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply eq_deeply re/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/trim :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant ERROR_LOG_BUFFER_SIZE => 2048;

my $t = Test::Nginx->new()->has(qw/http limit_req/)
	->plan(5)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_req_zone $binary_remote_addr zone=one:1m rate=1r/m;

    server {

        listen       127.0.0.1:8080;
        server_name  localhost;

        location /debug {

            limit_req zone=one;

            error_log %%TESTDIR%%/e_debug_debug.log  debug;
            error_log %%TESTDIR%%/e_debug_debug.json debug format=json;

            error_log %%TESTDIR%%/e_debug_info.log  info;
            error_log %%TESTDIR%%/e_debug_info.json info format=json;

            # normal and JSON outputs are intermixed in stderr
            error_log stderr debug;
            error_log stderr debug format=json;
        }

        location /info {
            limit_req zone=one;

            limit_req_log_level info;

            error_log %%TESTDIR%%/e_info_debug.log  debug;
            error_log %%TESTDIR%%/e_info_debug.json debug format=json;

            error_log %%TESTDIR%%/e_info_info.log  info;
            error_log %%TESTDIR%%/e_info_info.json info format=json;

            error_log %%TESTDIR%%/e_info_notice.log  notice;
            error_log %%TESTDIR%%/e_info_notice.json notice format=json;

            # normal and JSON outputs are intermixed in stderr
            error_log stderr info;
            error_log stderr info  format=json;
        }

        location /errno {
            error_log_user_tag "$arg_tag1";
            error_log_user_tag "$arg_tag2";

            error_log %%TESTDIR%%/errno.log error format=json;
        }

        location /trunc {
            limit_req zone=one;

            error_log_user_tag "$arg_tag";

            error_log %%TESTDIR%%/trunc.log error format=json;
        }

        location /tesc {
            limit_req zone=one;

            error_log_user_tag "$arg_tag";

            error_log %%TESTDIR%%/tesc.log error format=json;
        }
    }
}

EOF

my $d = $t->testdir();

open OLDERR, '>&', \*STDERR;
open STDERR, '>', $d . '/stderr' or die "Can't reopen STDERR: $!";
open my $stderr, '<', $d . '/stderr'
	or die "Can't open stderr file: $!";

$t->run();

open STDERR, '>&', \*OLDERR;

my $with_debug = $t->has_module('debug');

subtest 'prepare' => sub {

	# loglevels

	# charge limit_req
	http_get('/info');
	SKIP: {
		skip 'no --with-debug', 8 unless $with_debug;
		http_get('/debug');
	}

	http_get('/info');

	# errno
	like(http_get('/errno/404?tag1=bar'), qr/404/, '404 from missing file');

	# tag_escape
	like(http_get('/tesc/?tag=},broken"'), qr/503/, '503 from tesc');

	# truncation

	my $MAX_GOOD = 1670;
	my $long_file = 'x' x $MAX_GOOD;

	like(http_get("/trunc/$long_file?tag=3210"), qr/503/,
		"503 at len:$MAX_GOOD");

	for my $len (($MAX_GOOD + 1) .. ($MAX_GOOD + 100)) {
		$long_file = 'x' x $len;

		like(http_get("/trunc/$long_file?tag=3210"), qr/503/,
			"503 from /trunc len:$len");
	}
};

$t->stop();

###############################################################################

subtest 'loglevels' => sub {

	SKIP: {
		skip 'no --with-debug', 9 unless $with_debug;

		isnt($t->find_in_file('e_debug_debug.log', qr/\[debug\]/), 0,
			'some debug messages in debug_debug log');
		is($t->find_in_file('e_debug_info.log', qr/\[debug\]/), 0,
			'no debug messages in debug_info log');

		# read stderr once, filter twice on different patterns
		my @raw_lines = get_lines("$d/stderr");

		my @flines = filter_lines(\@raw_lines, '[debug]');
		isnt(@flines, 0, 'some debug messages in stderr');

		@flines = filter_lines(\@raw_lines, '"level":"debug"');
		isnt(@flines, 0, 'some json debug messages in stderr');

		@raw_lines = $t->find_in_file('e_debug_debug.json',
			quotemeta('"level":"debug"'));

		# actually, 70+ of them, but don't rely on count of debug messages
		ok(@raw_lines > 20, 'multiple basic json lines');

		my $nfails = verify_json_basic_lines(\@raw_lines, 'debug');
		is($nfails, 0, 'basic json logs');

		@raw_lines = $t->find_in_file('e_debug_debug.json',
			'limiting request');
		is(@raw_lines, 1, 'single http json line');

		$nfails = verify_json_http_lines(\@raw_lines, 'error');
		is($nfails, 0, 'http json debug logs');

		is($t->find_in_file('e_info_debug.log', qr/\[info\]/), 1,
			'file info debug');
	}

	is($t->find_in_file('e_info_info.log', qr/\[info\]/), 1,
		'file info info');
	is($t->find_in_file('e_info_notice.log', qr/\[info\]/), 0,
		'file info notice');

	# non-escaped pattern is NOT there
	my @raw_lines = get_lines("$d/stderr");
	my @flines = filter_lines(\@raw_lines, '[info]');
	isnt(@flines, 0, 'stderr info');

	@flines = filter_lines(\@raw_lines, '"level":"info"');
	isnt(@flines, 0, 'stderr json info');

	@raw_lines = get_lines("$d/e_info_debug.json");

	SKIP: {
		skip 'no --with-debug', 1 unless $with_debug;

		@flines = filter_lines(\@raw_lines, '"level":"debug"');
		isnt(@flines, 0, 'debug json messages in e_info_debug.json');
	}

	@flines = filter_lines(\@raw_lines, '"level":"info"');
	is(@flines, 1, 'info json messages in e_info_debug.json');

	@flines = filter_lines(\@raw_lines, 'limiting request');
	is(@flines, 1, 'single json error line');

	my $nfails = verify_json_http_lines(\@flines, 'info');
	is($nfails, 0, 'http json info log');
};

subtest 'errno' => sub {
	my @raw_lines = get_lines("$d/errno.log");
	is(@raw_lines, 1, 'single line in errno.log');

	my $extra = {
		error => {
			code    => $NUM_RE,
			message => 'No such file or directory'
		}
	};

	verify_json_log_http_entry($raw_lines[0], 'error', 'bar', $extra,
		'errno is correct in json');
};

subtest 'tag_escape' => sub {
	my @raw_lines = get_lines("$d/tesc.log");

	verify_json_log_http_entry($raw_lines[0], 'error', '},broken"', undef,
		'tag value escaped ok');
};

subtest 'truncation' => sub {

	# we exceeded error log buffer and JSON had to be truncated in various
	# places; ensure that all produced lines:
	# 1) are correct JSON
	# 2) have 'truncated' flag

	my $j = JSON->new();

	my @raw_lines = get_lines("$d/trunc.log");

	my $good_line = $raw_lines[1];

	ok(length($good_line) <= ERROR_LOG_BUFFER_SIZE,
		'the line length does not exceed error log buffer size');

	verify_json_log_http_entry($good_line, 'error', '3210', undef,
		'correct http json entry before truncation');

	my $expected_json = $j->decode($good_line);

	my $truncated;
	for my $i (2 .. $#raw_lines) {
		$expected_json->{connection}++;
		$expected_json->{message} = re(qr/limiting requests/);
		$expected_json->{http}{request}{request_line} = re(qr/GET \//);
		$expected_json->{time} = $TIME_RE;

		my $prev_request_len =
			length($expected_json->{http}{request}{request_line});

		my $slen = length($raw_lines[$i]);

		ok($slen <= ERROR_LOG_BUFFER_SIZE,
			"line $i length [$slen chars] does not exceed "
			. ERROR_LOG_BUFFER_SIZE);

		my $json;
		eval {
			$json = $j->decode($raw_lines[$i]);
		};
		if ($@) {
			undef $json;
			diag("Broken JSON line[$slen chars]: >>" . $raw_lines[$i] . '<<');
		}
		ok(defined $json, "line $i decoded OK");

		my $request_len = length($json->{http}{request}{request_line});

		my $ok = eq_deeply($json, $expected_json);

		if (!$truncated) {
			if ($ok) {
				pass("line $i is not truncated");
				ok($request_len > $prev_request_len, 'request len increased: '
					. "$prev_request_len -> $request_len");
			} else {
				$truncated = 1;
			}
		}

		if ($truncated) {
			is($json->{truncated}, JSON::true(), "line $i truncated True");
		}

		$expected_json = $json;
	}
};

###############################################################################

sub verify_json_basic_lines {
	my ($lines, $level) = @_;

	my $fails = 0;

	while (my ($k, $line) = each @{ $lines }) {
		my $ok = verify_json_log_basic_entry($line, $level,
			'basic json entry at line ' . ($k + 1));
		$fails++ unless $ok;
	}

	return $fails;
}

sub verify_json_http_lines {
	my ($lines, $level) = @_;

	my $fails = 0;

	while (my ($k, $line) = each @{ $lines }) {
		my $ok = verify_json_log_http_entry($line, $level, undef, undef,
			'http json entry at line ' . ($k + 1));
		$fails++ unless $ok;
	}

	return $fails;
}

sub verify_json_log_basic_entry {
	my ($line, $level, $msg) = @_;

	my $j = JSON->new();
	my $json = $j->decode($line);

	my $expected = {
		time       => $TIME_RE,
		pid        => $NUM_RE,
		tid        => $NUM_RE,
		level      => $level,
		connection => $NUM_RE,
		message    => re(qr/.*/)
	};
	$expected->{src} = re(qr/.*/)
		if $with_debug;

	my $ok = cmp_deeply($json, $expected, $msg);
	diag $line unless $ok;
	return $ok;
}

sub verify_json_log_http_entry {
	my ($line, $level, $tag, $extra, $msg) = @_;

	my $j = JSON->new();
	my $json = $j->decode($line);

	my @tags = ('http');

	if (defined $tag) {
		push @tags, $tag;
	}

	my $expected = {
		time       => $TIME_RE,
		pid        => $NUM_RE,
		tid        => $NUM_RE,
		level      => $level,
		connection => $NUM_RE,
		message    => re(qr/.*/),
		http => {
			client  => '127.0.0.1',
			request => {
				server       => 'localhost',
				request_line => re(qr/GET \//),
				host         => 'localhost'
			},
		},
		tags => \@tags,
		%{ $extra // {}}
	};
	$expected->{src} = re(qr/.*/)
		if $with_debug;

	my $ok = cmp_deeply($json, $expected, $msg);
	diag $line unless $ok;
	return $ok;
}

###############################################################################

sub filter_lines {
	my ($inlines, $pattern) = @_;
	my @outlines = grep { /\Q$pattern\E/ } @{ $inlines };
	return @outlines;
}

sub get_lines {
	my ($file) = @_;

	open my $fh, '<', $file or return "$!";

	my @lines;
	for my $line (<$fh>) {
		$line = trim($line);
		push @lines, $line;
	}

	return @lines;
}

###############################################################################
