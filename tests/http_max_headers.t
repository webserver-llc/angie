#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for max_headers directive.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        max_headers 5;

        location / {
            return 204;
        }
    }
}

EOF

$t->try_run('no max_headers')->plan(3);

###############################################################################

like(get('/'), qr/ 204/, 'two headers');
like(get('/', ('Foo: bar') x 3), qr/ 204/, 'five headers');
like(get('/', ('Foo: bar') x 4), qr/ 400/, 'six headers rejected');

###############################################################################

sub get {
	my ($url, @headers) = @_;
	return http(
		"GET $url HTTP/1.1" . CRLF .
		'Host: localhost' . CRLF .
		'Connection: close' . CRLF .
		join(CRLF, @headers) . CRLF . CRLF
	);
}

###############################################################################
