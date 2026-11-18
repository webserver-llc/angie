#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for HTTP/3 client upstream response where HEADERS frame is received
# in multiple reads.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite http_v3/)
	->has_daemon('openssl')->plan(2);

$t->prepare_ssl();

my $set = '';

for my $i (1 .. 80) {
	my $n = sprintf('%02d', $i);
	$set .= "            add_header X-Set-$n header-value-$n"
		. "-0123456789abcdefg;\n";
}

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_http_version  3;
            proxy_pass https://u;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        limit_rate 1024;

        location / {
            $set
            return 200 "";
        }
    }
}

EOF

$t->run();

###############################################################################

my ($res, $found);

$res = http_get('/');

like($res, qr/^HTTP\/1\.1 200/, 'status is 200');

$found = 0;
for my $i (1 .. 80) {
	my $n = sprintf('%02d', $i);
	$found++ if $res =~ m/X-Set-\Q$n\E: header-value-\Q$n\E/i;
}

is($found, 80, 'all header lines received');

###############################################################################
