#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for stream proxy to ssl backend, proxy_ssl_conf_command.

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

my $t = Test::Nginx->new()->has(qw/stream stream_ssl stream_return/)
	->has_daemon('openssl');

$t->{_configure_args} =~ /OpenSSL ([\d\.]+)/;
plan(skip_all => 'OpenSSL too old') unless defined $1 and $1 ge '1.0.2';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen       127.0.0.1:8080;
        proxy_pass   127.0.0.1:8081;
        proxy_ssl    on;

        proxy_ssl_certificate localhost.crt;
        proxy_ssl_certificate_key localhost.key;
        proxy_ssl_conf_command Certificate override.crt;
        proxy_ssl_conf_command PrivateKey override.key;
    }

    server {
        listen       127.0.0.1:8081 ssl;
        return       $ssl_client_s_dn;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        ssl_verify_client optional_no_ca;
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

my $d = $t->testdir();

foreach my $name ('localhost', 'override') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('index.html', '');
$t->try_run('no proxy_ssl_conf_command')->plan(1);

###############################################################################

like(stream('127.0.0.1:' . port(8080))->read(), qr/CN=override/,
	'Certificate');

###############################################################################
