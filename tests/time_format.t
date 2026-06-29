#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for time_format directive.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    time_format $time_iso8601_ms    "%Y-%m-%dT%H:%M:%S.%L%Z";
    time_format $time_clf           "%d/%b/%Y:%H:%M:%S %z";
    time_format $time_names         "%A, %d %B %Y";
    time_format $time_percent       "100%%";
    time_format $time_12h           "%I:%M:%S %p";
    time_format $time_empty         "";
    time_format $time_trailing_pct  "abc%";
    time_format $time_unknown_spec  "%Q";
    time_format $time_e             "%e";
    time_format $time_P             "%P";
    time_format $time_a             "%a";
    time_format $time_bh            "%b|%h";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            add_header X-ISO8601-MS   $time_iso8601_ms;
            add_header X-CLF          $time_clf;
            add_header X-Names        $time_names;
            add_header X-Percent      $time_percent;
            add_header X-12H          $time_12h;
            add_header X-Empty        $time_empty;
            add_header X-TrailingPct  $time_trailing_pct;
            add_header X-UnknownSpec  $time_unknown_spec;
            add_header X-E            $time_e;
            add_header X-P            $time_P;
            add_header X-A            $time_a;
            add_header X-BH           $time_bh;
        }
    }
}

EOF

$t->write_file('index.html', '');

$t->run();

###############################################################################

my $r = http_head('/');

# ISO 8601 with milliseconds: 2024-01-15T14:34:56.789+03:00
like($r,
	qr/X-ISO8601-MS: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}/,
	'iso8601 with milliseconds');

like($r, qr/X-ISO8601-MS: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{3})[+-]/,
	'milliseconds are 3 digits');

# CLF format: 15/Jan/2024:14:34:56 +0300
like($r,
	qr|X-CLF: \d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}|,
	'CLF format');

like($r,
	qr/X-Names:
		\ (?:Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday),
		\ \d{2}
		\ (?:January|February|March|April|May|June|July|August
			|September|October|November|December)
		\ \d{4}/x,
	'full weekday and month names');

like($r, qr/X-Percent: 100%/, 'percent escape');

like($r, qr/X-12H: (?:0[1-9]|1[0-2]):\d{2}:\d{2} (?:AM|PM)/, '12-hour clock');

# Empty format string produces empty value
unlike($r, qr/X-Empty:/, 'empty format string (no header)');

# Trailing lone % at end of format is silently dropped
like($r, qr/X-TrailingPct: abc\r\n/, 'trailing lone percent gives literal abc');

# Unknown specifier %Q is passed through as-is: "%Q"
like($r, qr/X-UnknownSpec: %Q/, 'unknown specifier passed through');

# %e: space-padded day — first char is space or 1-9, never 0
like($r, qr/X-E: [ 1-9]\d/, 'space-padded day');

like($r, qr/X-P: (?:am|pm)/, 'lowercase am/pm');

like($r, qr/X-A: (?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)/, 'abbreviated weekday');

# %h must produce the same abbreviated month name as %b
like($r, qr/X-BH: ([A-Z][a-z]{2})\|\1/, '%h same as %b');
