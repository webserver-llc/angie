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
use Test::Utils qw/:re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant ERROR_LOG_BUFFER_SIZE => 2048;

my $t = Test::Nginx->new()->has(qw/http limit_req/)
	->write_file_expand('nginx.conf', <<'EOF');

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

        location /order { # error_log order matters
            limit_req zone=one;

            error_log %%TESTDIR%%/e_order_error.json error format=json;
            error_log %%TESTDIR%%/e_order_warn.json  warn  format=json;
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

$t->try_run('Angie was built without support for JSON')
	->plan(6)
	->skip_stderr_check();

my $with_debug = $t->has_module('debug');

subtest 'prepare' => sub {

	# loglevels

	# charge limit_req
	http_get('/info');
	http_get('/order');
	http_get('/debug');
	http_get('/info');
	http_get('/order');

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
	# read stderr once, then filter on different patterns
	my @stderr_lines = $t->get_file_lines('stderr');

	my @e_debug_info_log_lines  = $t->get_file_lines('e_debug_info.log');
	my @e_debug_info_json_lines = $t->get_file_lines('e_debug_info.json');

	if ($with_debug) {
		isnt($t->find_in_file('e_debug_debug.log', '[debug]'), 0,
			'some debug messages in debug_debug log');

		isnt(filter_lines(\@stderr_lines, '[debug]'), 0,
			'some debug messages in stderr');

		isnt(filter_lines(\@stderr_lines, '"level":"debug"'), 0,
			'some json debug messages in stderr');
	} else {
		is($t->find_in_file('e_debug_debug.log', '[debug]'), 0,
			'no debug messages in debug_debug log');

		is(filter_lines(\@stderr_lines, '[debug]'), 0,
			'no debug messages in stderr');

		is(filter_lines(\@stderr_lines, '"level":"debug"'), 0,
			'no json debug messages in stderr');
	}

	my @e_debug_debug_json_lines = $t->get_file_lines('e_debug_debug.json');
	my @e_debug_debug_json_flines = filter_lines(\@e_debug_debug_json_lines,
		'"level":"debug"');

	verify_json_basic_lines(\@e_debug_debug_json_flines, 'debug',
			'no bad lines in basic json logs');

	if ($with_debug) {
		# actually, 70+ of them, but don't rely on count of debug messages
		ok(@e_debug_debug_json_flines > 20, 'multiple basic json lines');
	} else {
		is(@e_debug_debug_json_flines, 0, 'no basic json lines');
	}

	my @flines = filter_lines(\@e_debug_debug_json_lines, 'limiting request');
	is(@flines, 1, 'single http json line');
	verify_json_http_lines(\@flines, 'error', 'http json debug logs');

	is(filter_lines(\@e_debug_info_log_lines, '[debug]'), 0,
		'no debug messages in debug_info log');

	is(filter_lines(\@e_debug_info_json_lines, '"level":"debug"'), 0,
		'no debug messages in debug_info json log');

	is(filter_lines(\@e_debug_info_log_lines, prepare_log_re('error')), 1,
		'error messages in debug_info log');

	is(@e_debug_info_json_lines, 1,
		'single error message om debug_info json log');
	verify_json_http_lines(\@e_debug_info_json_lines, 'error',
		'error messages in debug_info json log');

	my $log_re = prepare_log_re('info');
	is($t->find_in_file('e_info_debug.log', $log_re), 1, 'file info debug');
	is($t->find_in_file('e_info_info.log', $log_re), 1, 'file info info');
	is($t->find_in_file('e_info_notice.log', $log_re), 0, 'file info notice');

	isnt(filter_lines(\@stderr_lines, $log_re), 0, 'stderr info');

	isnt(filter_lines(\@stderr_lines, '"level":"info"'), 0,
		'stderr json info');

	my @raw_lines = $t->get_file_lines('e_info_debug.json');

	@flines = filter_lines(\@raw_lines, '"level":"debug"');
	if ($with_debug) {
		isnt(@flines, 0, 'debug json messages in e_info_debug.json');
	} else {
		is(@flines, 0, 'no debug json messages in e_info_debug.json');
	}

	is(filter_lines(\@raw_lines, '"level":"info"'), 1,
		'info json messages in e_info_debug.json');

	@flines = filter_lines(\@raw_lines, 'limiting request');
	is(@flines, 1, 'single json error line');
	verify_json_http_lines(\@flines, 'info', 'http json info log');

	@raw_lines = $t->get_file_lines('e_info_info.json');

	is(filter_lines(\@raw_lines, '"level":"debug"'), 0,
		'no debug json messages in e_info_info.json');

	is(filter_lines(\@raw_lines, '"level":"info"'), 1,
		'info json messages in e_info_info.json');

	@flines = filter_lines(\@raw_lines, 'limiting request');
	is(@flines, 1, 'single json error line');
	verify_json_http_lines(\@flines, 'info', 'http json info log');

	@raw_lines = $t->get_file_lines('e_info_notice.json');

	is(filter_lines(\@raw_lines, '"level":"debug"'), 0,
		'no debug json messages in e_info_notice.json');

	is(filter_lines(\@raw_lines, '"level":"info"'), 0,
		'no info json messages in e_info_notice.json');
};

subtest 'error_log order matters' => sub {
	for my $f (qw(e_order_error.json e_order_warn.json)) {
		my @lines = $t->get_file_lines($f);
		verify_json_http_lines(\@lines, 'error', "no bad lines in $f log");
		is(@lines, 2, "2 lines in $f log");
	}
};

subtest 'errno' => sub {
	my @raw_lines = $t->get_file_lines('errno.log');
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
	my @raw_lines = $t->get_file_lines('tesc.log');

	verify_json_log_http_entry($raw_lines[0], 'error', '},broken"', undef,
		'tag value escaped ok');
};

subtest 'truncation' => sub {

	# we exceeded error log buffer and JSON had to be truncated in various
	# places; ensure that all produced lines:
	# 1) are correct JSON
	# 2) have 'truncated' flag

	my $j = JSON->new();

	my @raw_lines = $t->get_file_lines('trunc.log');

	my $good_line = $raw_lines[1];

	ok(length($good_line) <= ERROR_LOG_BUFFER_SIZE,
		'the line length does not exceed error log buffer size');

	verify_json_log_http_entry($good_line, 'error', '3210', undef,
		'correct http json entry before truncation');

	my $expected_json = $j->decode($good_line);

	my $prev_request_len =
		length($expected_json->{http}{request}{request_line});

	$expected_json->{message} = re(qr/limiting requests/);
	$expected_json->{http}{request}{request_line} = re(qr/GET \//);
	$expected_json->{time} = $TIME_RE;

	for my $i (2 .. $#raw_lines) {
		$expected_json->{connection}++;

		my $raw_line = $raw_lines[$i];
		my $slen = length($raw_line);

		ok($slen <= ERROR_LOG_BUFFER_SIZE,
			"line $i length [$slen chars] does not exceed "
			. ERROR_LOG_BUFFER_SIZE);

		my $json;
		eval {
			$json = $j->decode($raw_line);
		};
		if ($@) {
			undef $json;
			diag("Broken JSON line[$slen chars]: >>$raw_line<<");
		}
		ok(defined $json, "line $i decoded OK")
			or next;

		my $request_len = length($json->{http}{request}{request_line});

		my $ok = eq_deeply($json, $expected_json);
		if ($ok && $request_len >= $prev_request_len) {
			is($json->{truncated}, undef, "line $i truncated False")
				or diag $raw_line;
		} else {
			is($json->{truncated}, JSON::true(), "line $i truncated True")
				or diag $raw_line;
		}

		$prev_request_len = $request_len;
	}
};

###############################################################################

sub prepare_log_re {
	my $level = shift;

	return qr/
		^
		\d{4}\/\d{2}\/\d{2} \s \d{2}:\d{2}:\d{2} # datetime
		\s+
		\[ $level \]
		\s+
		\d+ \# \d+ :                             # pid#tid
		\s+
		\* \d+                                   # connection_id
		\s+
		limiting \s requests, \s excess: \s [\d.]+ \s+ by \s zone \s "one" ,
		\s+ client: \s "127\.0\.0\.1" ,
		\s+ server: \s "localhost" ,
		\s+ request_line: \s "[^"]+" ,
		\s+ host: \s "localhost"
		$
	/x;
}

sub verify_json_basic_lines {
	my ($lines, $level, $msg) = @_;

	my $fails = 0;

	while (my ($k, $line) = each @{ $lines }) {
		my $ok = verify_json_log_basic_entry($line, $level,
			'basic json entry at line ' . ($k + 1));
		$fails++ unless $ok;
	}

	is($fails, 0, $msg);
}

sub verify_json_http_lines {
	my ($lines, $level, $msg) = @_;

	my $fails = 0;

	while (my ($k, $line) = each @{ $lines }) {
		my $ok = verify_json_log_http_entry($line, $level, undef, undef,
			'http json entry at line ' . ($k + 1));
		$fails++ unless $ok;
	}

	is($fails, 0, $msg);
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
		http       => {
			client  => '127.0.0.1',
			request => {
				server       => 'localhost',
				request_line => re(qr/GET \//),
				host         => 'localhost'
			},
		},
		tags       => \@tags,
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

	$pattern = qr/\Q$pattern\E/ if ref($pattern) eq '';
	my @outlines = grep { /$pattern/ } @{ $inlines };

	return @outlines;
}

