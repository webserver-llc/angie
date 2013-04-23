#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for embedded perl module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http perl rewrite/)->plan(7)
	->write_file_expand('nginx.conf', <<'EOF');

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
            set $testvar "TEST";
            perl 'sub {
                use warnings;
                use strict;

                my $r = shift;

                $r->send_http_header("text/plain");

                return OK if $r->header_only;

                my $v = $r->variable("testvar");

                $r->print("$v");

                return OK;
            }';
        }

        location /body {
            perl 'sub {
                use warnings;
                use strict;

                my $r = shift;

                if ($r->has_request_body(\&post)) {
                    return OK;
                }

                return HTTP_BAD_REQUEST;

                sub post {
                    my $r = shift;
                    $r->send_http_header;
                    $r->print("body: ", $r->request_body, "\n");
                    $r->print("file: ", $r->request_body_file, "\n");
                }
            }';
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/'), qr/TEST/, 'perl response');

like(http(
	'GET /body HTTP/1.0' . CRLF
	. 'Host: localhost' . CRLF
	. 'Content-Length: 10' . CRLF . CRLF
	. '1234567890'
), qr/body: 1234567890/, 'perl body preread');

like(http(
	'GET /body HTTP/1.0' . CRLF
	. 'Host: localhost' . CRLF
	. 'Content-Length: 10' . CRLF . CRLF,
	sleep => 0.1,
	body => '1234567890'
), qr/body: 1234567890/, 'perl body late');

TODO: {
local $TODO = 'broken' if $t->has_version('1.3.9');

like(http(
	'GET /body HTTP/1.0' . CRLF
	. 'Host: localhost' . CRLF
	. 'Content-Length: 10' . CRLF . CRLF
	. '12345',
	sleep => 0.1,
	body => '67890'
), qr/body: 1234567890/, 'perl body split');

}

TODO: {
local $TODO = 'not yet';

like(http(
	'GET /body HTTP/1.1' . CRLF
	. 'Host: localhost' . CRLF
	. 'Connection: close' . CRLF
	. 'Transfer-Encoding: chunked' . CRLF . CRLF
	. 'a' . CRLF
	. '1234567890' . CRLF
	. '0' . CRLF . CRLF
), qr/body: 1234567890/, 'perl body chunked');

like(http(
	'GET /body HTTP/1.1' . CRLF
	. 'Host: localhost' . CRLF
	. 'Connection: close' . CRLF
	. 'Transfer-Encoding: chunked' . CRLF . CRLF,
	sleep => 0.1,
	body => 'a' . CRLF . '1234567890' . CRLF . '0' . CRLF . CRLF
), qr/body: 1234567890/, 'perl body chunked late');

like(http(
	'GET /body HTTP/1.1' . CRLF
	. 'Host: localhost' . CRLF
	. 'Connection: close' . CRLF
	. 'Transfer-Encoding: chunked' . CRLF . CRLF
	. 'a' . CRLF
	. '12345',
	sleep => 0.1,
	body => '67890' . CRLF . '0' . CRLF . CRLF
), qr/body: 1234567890/, 'perl body chunked split');

}

###############################################################################
