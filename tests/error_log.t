#!/usr/bin/perl

# (C) 2025 Web Server LLC
# (C) Nginx, Inc.

# Tests for error_log.
# Various log levels emitted with limit_req_log_level.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http limit_req/)
	->plan(6)
	->skip_api_check() # api check does not work with global limit_req
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_req_zone $binary_remote_addr zone=one:1m rate=1r/m;
    limit_req zone=one;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /debug {
            error_log %%TESTDIR%%/e_debug_debug.log debug;
            error_log %%TESTDIR%%/e_debug_info.log info;
            error_log stderr debug;
        }
        location /info {
            limit_req_log_level info;
            error_log %%TESTDIR%%/e_info_debug.log debug;
            error_log %%TESTDIR%%/e_info_info.log info;
            error_log %%TESTDIR%%/e_info_notice.log notice;
            error_log stderr info;
        }
        location /notice {
            limit_req_log_level notice;
            error_log %%TESTDIR%%/e_notice_info.log info;
            error_log %%TESTDIR%%/e_notice_notice.log notice;
            error_log %%TESTDIR%%/e_notice_warn.log warn;
            error_log stderr notice;
        }
        location /warn {
            limit_req_log_level warn;
            error_log %%TESTDIR%%/e_warn_notice.log notice;
            error_log %%TESTDIR%%/e_warn_warn.log warn;
            error_log %%TESTDIR%%/e_warn_error.log error;
            error_log stderr warn;
        }
        location /error {
            error_log %%TESTDIR%%/e_error_warn.log warn;
            error_log %%TESTDIR%%/e_error_error.log;
            error_log %%TESTDIR%%/e_error_alert.log alert;
            error_log stderr;
        }

        location /file_low {
            error_log %%TESTDIR%%/e_multi_low.log warn;
            error_log %%TESTDIR%%/e_multi_low.log;
        }
        location /file_dup {
            error_log %%TESTDIR%%/e_multi.log;
            error_log %%TESTDIR%%/e_multi.log;
        }
        location /file_high {
            error_log %%TESTDIR%%/e_multi_high.log emerg;
            error_log %%TESTDIR%%/e_multi_high.log;
        }

        location /stderr_low {
            error_log stderr warn;
            error_log stderr;
        }
        location /stderr_dup {
            error_log stderr;
            error_log stderr;
        }
        location /stderr_high {
            error_log stderr emerg;
            error_log stderr;
        }
    }
}

EOF

$t->run()->skip_stderr_check();

open my $stderr, '<', $t->testdir() . '/stderr'
	or die "Can't open stderr file: $!";

###############################################################################

# charge limit_req

http_get('/');

subtest 'debug' => sub {
	http_get('/debug');
	if ($t->has_module('debug')) {
		isnt($t->find_in_file('e_debug_debug.log', '[debug]'), 0,
			'file debug debug');
		isnt($t->find_in_file('stderr', '[debug]'), 0, 'stderr debug');
	} else {
		is($t->find_in_file('e_debug_debug.log', '[debug]'), 0,
			'file debug debug');
		is($t->find_in_file('stderr', '[debug]'), 0, 'stderr debug');
	}
	is($t->find_in_file('e_debug_info.log', '[debug]'), 0, 'file debug info');
	verify_log_lines($t, 'e_debug_info.log', 'error', 1);
};

subtest 'info' => sub {
	http_get('/info');
	is($t->find_in_file('e_info_debug.log', prepare_log_re('info')), 1,
		'file info debug');
	verify_log_lines($t, 'e_info_info.log', 'info', 1);
	is($t->find_in_file('e_info_notice.log', '[info]'), 0, 'file info notice');
	verify_stderr_lines('info', 1, 'stderr info');
};

subtest 'notice' => sub {
	http_get('/notice');
	verify_log_lines($t, 'e_notice_info.log', 'notice', 1);
	verify_log_lines($t, 'e_notice_notice.log', 'notice', 1);
	is($t->find_in_file('e_notice_warn.log', '[notice]'), 0,
		'file notice warn');
	verify_stderr_lines('notice', 1, 'stderr notice');
};

subtest 'warn' => sub {
	http_get('/warn');
	verify_log_lines($t, 'e_warn_notice.log', 'warn', 1);
	verify_log_lines($t, 'e_warn_warn.log', 'warn', 1);
	is($t->find_in_file('e_warn_error.log', '[warn]'), 0, 'file warn error');
	verify_stderr_lines('warn', 1, 'stderr warn');
};

subtest 'error' => sub {
	http_get('/error');
	verify_log_lines($t, 'e_error_warn.log', 'error', 1);
	verify_log_lines($t, 'e_error_error.log', 'error', 1);
	is($t->find_in_file('e_error_alert.log', '[error]'), 0,
		'file error alert');
	verify_stderr_lines('error', 1, 'stderr error');
};

# count log messages emitted with various error_log levels
subtest 'various error_log levels' => sub {
	http_get('/file_low');
	verify_log_lines($t, 'e_multi_low.log', 'error', 2);

	http_get('/file_dup');
	verify_log_lines($t, 'e_multi.log', 'error', 2);

	http_get('/file_high');
	verify_log_lines($t, 'e_multi_high.log', 'error', 1);

	http_get('/stderr_low');
	verify_stderr_lines('error', 2, 'stderr low');

	http_get('/stderr_dup');
	verify_stderr_lines('error', 2, 'stderr dup');

	http_get('/stderr_high');
	verify_stderr_lines('error', 1, 'stderr high');
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

sub verify_log_lines {
	my ($t, $log_name, $level, $total_lines) = @_;

	my $log_re = prepare_log_re($level);

	my @lines = $t->get_file_lines($log_name);
	while (my ($k, $line) = each @lines) {
		like($line, $log_re, "$log_name line $k is ok");
	}
	is(@lines, $total_lines, "$total_lines line(s) in $log_name");
}

sub verify_stderr_lines {
	my ($level, $total_lines, $tname) = @_;

	my $pattern = prepare_log_re($level);

	my @value = grep { /$pattern/ } (<$stderr>);
	$stderr->clearerr();

	is(@value, $total_lines, "$tname: $total_lines line(s)");
}

###############################################################################
