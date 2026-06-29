#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for time_format directive in stream context.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return/)->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    time_format $time_iso8601_ms   "%Y-%m-%dT%H:%M:%S.%L%Z";
    time_format $time_clf_stream   "%d/%b/%Y:%H:%M:%S %z";
    time_format $time_names_stream "%A, %d %B %Y";
    time_format $time_nt           "A%tB|X%nY";

    log_format tf
        '$time_iso8601_ms|$time_clf_stream|$time_names_stream|$time_nt';

    access_log %%TESTDIR%%/stream_time_format.log tf;

    server {
        listen  127.0.0.1:8080;
        return  "OK";
    }
}

EOF

$t->run();

stream('127.0.0.1:' . port(8080))->read();

$t->stop();

my $log = $t->read_file('stream_time_format.log');

like($log,
	qr/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}/,
	'stream: iso8601 with milliseconds');

like($log,
	qr|\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}|,
	'stream: CLF format');

like($log,
	qr/(?:Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday),
		\ \d{2}
		\ (?:January|February|March|April|May|June|July|August
			|September|October|November|December)
		\ \d{4}/x,
	'stream: full weekday and month names');

like($log, qr/A\\x09B\|X\\x0AY/, 'tab and newline specifiers');
