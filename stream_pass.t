#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream pass module.

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

my $t = Test::Nginx->new()
	->has(qw/stream stream_ssl stream_pass stream_ssl_preread/)
	->has(qw/http http_ssl sni socket_ssl_sni/)->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format test $status;
    access_log %%TESTDIR%%/test.log test;

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8443 ssl;
        server_name  default;
        pass         127.0.0.1:8092;

        ssl_preread  on;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  sni;
        pass         127.0.0.1:8091;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  sni;
        pass         127.0.0.1:8092;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8091 ssl;
        listen       127.0.0.1:8092;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

$t->write_file('index.html', '');

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->try_run('no pass module')->plan(5);

###############################################################################

# passing either to HTTP or HTTPS backend, depending on server_name

like(http_get('/'), qr/200 OK/, 'pass');
like(http_get('/', SSL => 1, SSL_hostname => 'sni',
	PeerAddr => '127.0.0.1:' . port(8080)), qr/200 OK/, 'pass ssl');

like(http_get('/', SSL => 1, SSL_hostname => 'sni'), qr/200 OK/,
	'pass ssl handshaked');

unlike(http_get('/', SSL => 1), qr/200 OK/, 'pass with preread');

$t->stop();

is($t->read_file('test.log'), "500\n", 'pass with preread - log');

###############################################################################
