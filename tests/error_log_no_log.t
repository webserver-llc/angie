#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for default error_log.

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
	->write_file_expand('nginx.conf', <<'EOF', 'no_error_log');

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

        location / {
            limit_req zone=one;
        }
    }
}

EOF

$t->write_file('index.html', 'SEE-THIS');
$t->run();

###############################################################################

# charge limit_req

like(http_get('/'), qr/SEE/, '1st request');
like(http_get('/'), qr/503/, '2nd request');
like(http_get('/'), qr/503/, '3rd request');

$t->stop();

verify_log_lines($t, 'error.log', 'error', 2);

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
	my @flines = grep { /\[$level\]/ } @lines;

	while (my ($k, $line) = each @flines) {
		like($line, $log_re, "$log_name line $k is ok");
	}
	is(@flines, $total_lines, "$total_lines line(s) in $log_name");
}

###############################################################################
