#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for HTTP/3 client stream limits accounting

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
	->has(qw/upstream_keepalive/)->has_daemon('openssl')->plan(5);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%%;

        keepalive 1;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_http_version        3;
            proxy_http3_max_concurrent_streams 2;

            proxy_pass https://u;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        location / {
            add_header X-Connection $quic_connection;
            return 200 "OK\n";
        }
    }
}

EOF

$t->run();

###############################################################################

my ($res, $c1, $c2, $c3);

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 1 is 200');
($c1) = $res =~ m/x-connection: (\d+)/;

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 2 is 200');
($c2) = $res =~ m/x-connection: (\d+)/;
is($c2, $c1, 'request 2 reused upstream connection');

$res = http_get('/');
like($res, qr/HTTP\/1\.1 200/, 'request 3 is 200');
($c3) = $res =~ m/x-connection: (\d+)/;
is($c3, $c1, 'request 3 reused upstream connection');

###############################################################################
