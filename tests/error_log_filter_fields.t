#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log fields filtering

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


my $t = Test::Nginx->new()->has(qw/http realip/)
	->plan(16)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {

        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {

            log_not_found on;

            error_log %%TESTDIR%%/filtered1.log
                      filter=request:/f1;

            error_log %%TESTDIR%%/filtered2.log
                      filter=request:/f2;

            error_log %%TESTDIR%%/filtered_fields_all.log;
        }

        location /client {

            log_not_found on;

            set_real_ip_from 127.0.0.1;
            real_ip_header    X-Forwarded-For;

            error_log %%TESTDIR%%/filtered_client1.log
                      filter=client:192.168.33.33;

            error_log %%TESTDIR%%/filtered_client2.log
                      filter=client:192.168.44.44;


            error_log %%TESTDIR%%/filtered_clients_all.log;
        }
    }
}

EOF


$t->run();

like(http_get('/foo'), qr/404/, 'generic query');
like(http_get('/f1'), qr/404/, 'query f1');
like(http_get('/f2'), qr/404/, 'query f2');

like(http_sp_xff('/client/foo', '192.168.1.1'), qr/404/, 'generic client query');
like(http_sp_xff('/client/f1', '192.168.33.33'), qr/404/, 'query client f1');
like(http_sp_xff('/client/f2', '192.168.44.44'), qr/404/, 'query client f2');

$t->stop();

is($t->find_in_file('filtered_fields_all.log', 'request:'), 3,
	'logged into filtered_fields_all.log');

is($t->find_in_file('filtered1.log', 'request:'), 1,
	'single message in filtered1.log');
is($t->find_in_file('filtered1.log', qr/f1/), 1,
	'filtered field1 correct message');

is($t->find_in_file('filtered2.log', 'request:'), 1,
	'single message in filtered2.log');
is($t->find_in_file('filtered2.log', qr/f2/), 1,
	'filtered field2 correct message');


is($t->find_in_file('filtered_clients_all.log', 'request:'), 3,
	'logged into filtered_clients_all.log');

is($t->find_in_file('filtered_client1.log', 'request:'), 1,
	'single message in filtered_client1.log');
is($t->find_in_file('filtered_client1.log', qr/192.168.33.33/), 1,
	'filtered client1 correct message');

is($t->find_in_file('filtered_client2.log', 'request:'), 1,
	'single message in filtered_client2.log');
is($t->find_in_file('filtered_client2.log', qr/192.168.44.44/), 1,
	'filtered client2 correct message');


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

