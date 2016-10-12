#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Test for msie_refresh in subrequests.

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

my $t = Test::Nginx->new()->has(qw/http rewrite ssi/)->plan(1)
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
            ssi on;
        }
        location /ssi {
            msie_refresh on;
            return 301;
        }
    }
}

EOF

$t->write_file('index.html', 'X<!--#include virtual="/ssi.html" -->X');
$t->run();

###############################################################################

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.11.5');

my $r = get('/', 'User-Agent: MSIE foo');
unlike($r, qr/\x0d\x0a?0\x0d\x0a?\x0d\x0a?\w/, 'only final chunk');

}

###############################################################################

sub get {
	my ($url, $extra) = @_;
	return http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
}

###############################################################################
