#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for basic error_log filters

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $bad_msg = 'invalid URL prefix in \"http://\", client: \"127.0.0.1\",'
	. ' server: \"localhost\", request_line: \"GET /bad HTTP/1.0\",'
	. ' host: \"localhost\"';

my $t = Test::Nginx->new()->has(qw/http realip rewrite proxy/)
	->plan(18)->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

error_log default.log;
error_log filtered_exact.log "filter=logline:=$bad_msg";
error_log filtered_substring.log filter=logline:127.0.0.3;
error_log filtered_regex.log filter=logline:~127\.0\.0\.4;

# two logs into one file
error_log filtered_or.log filter=logline:127.0.0.3;
error_log filtered_or.log filter=logline:~127\.0\.0\.4;

# multiple filters, all match
error_log filtered_and.log filter=logline:127.0.0.3
                           filter=logline:localhost
                           filter=logline:~HTTP;

# multiple filters, one does not match
error_log filtered_and_miss.log filter=logline:localhost
                                filter=logline:no_such_thing;

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            log_not_found on;
            set_real_ip_from  127.0.0.1;
            real_ip_header    X-Forwarded-For;
        }

        location /bad {
            # set empty variable to trigger runtime error on proxying
            set \$missing "";
            proxy_pass http://\$missing;
            # generates error without system-specific errno and paths
       }
    }
}

EOF


$t->run();

like(http_sp_xff('/foo', '127.0.0.1'), qr/404/, 'generic client query');
like(http_sp_xff('/f1', '127.0.0.2'), qr/404/, 'query client f1');
like(http_sp_xff('/f2', '127.0.0.3'), qr/404/, 'query client f2');
like(http_sp_xff('/f2', '127.0.0.4'), qr/404/, 'query client f3');

like(http_get('/bad'), qr/500/, 'triggered exact error');

$t->stop();

is($t->find_in_file('default.log', qr/.+/),  5, 'five errors in default log');

is($t->find_in_file('filtered_exact.log', qr/.+/), 1,
	'one line on exact match');

is($t->find_in_file('filtered_exact.log', $bad_msg), 1,
	'exact match is correct');

is($t->find_in_file('filtered_substring.log', qr/.+/), 1,
	'one line on substring match');
is($t->find_in_file('filtered_substring.log', qr/127\.0\.0\.3/), 1,
	'substring match is correct');

is($t->find_in_file('filtered_regex.log', qr/.+/), 1,
	'one line on regex match');
is($t->find_in_file('filtered_regex.log', qr/127\.0\.0\.4/), 1,
	'regex match is correct');

is($t->find_in_file('filtered_or.log', qr/.+/), 2, 'two lines in ORed log');
is($t->find_in_file('filtered_or.log', qr/127\.0\.0\.3/), 1,
	'substring match in ORed log');
is($t->find_in_file('filtered_or.log', qr/127\.0\.0\.4/), 1,
	'regex in ORed log');

is($t->find_in_file('filtered_and.log', qr/.+/), 1,
	'one line in ANDed log');
is($t->find_in_file('filtered_and.log', qr/127\.0\.0\.3/), 1,
	'subsing match in ANDed log');

is($t->find_in_file('filtered_and_miss.log', qr/.+/), 0,
	'empty non-matching multi filter');

###############################################################################

sub http_sp_xff {
	my ($url, $xff) = @_;

	my $s = http(<<EOF, start => 1);
GET $url HTTP/1.0
Host: localhost
X-Forwarded-For: $xff

EOF

	return ($s->sockport(), http_end($s));
}

