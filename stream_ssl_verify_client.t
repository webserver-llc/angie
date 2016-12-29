#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream ssl module, ssl_verify_client.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval {
	require Net::SSLeay;
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
};
plan(skip_all => 'Net::SSLeay not installed') if $@;

my $t = Test::Nginx->new()->has(qw/stream stream_ssl stream_return/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    ssl_verify_client optional_no_ca;

    server {
        listen  127.0.0.1:8080 ssl;
        return  $ssl_client_verify;

        ssl_client_certificate client.crt;
    }

    server {
        listen  127.0.0.1:8081 ssl;
        return  $ssl_client_verify;
    }
}

EOF

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

foreach my $name ('localhost', 'client') {
	system('openssl req -x509 -new '
		. "-config '$d/openssl.conf' -subj '/CN=$name/' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

my $ctx = Net::SSLeay::CTX_new() or die("Failed to create SSL_CTX $!");
Net::SSLeay::set_cert_and_key($ctx, "$d/client.crt", "$d/client.key") or die;

$t->try_run('no ssl_verify_client')->plan(2);

###############################################################################

my ($s, $ssl) = get_ssl_socket(port(8080));
is(Net::SSLeay::read($ssl), 'SUCCESS', 'success');

($s, $ssl) = get_ssl_socket(port(8081));
like(Net::SSLeay::read($ssl), qr/FAILED/, 'failed');

###############################################################################

sub get_ssl_socket {
	my ($port) = @_;

	my $dest_ip = inet_aton('127.0.0.1');
	my $dest_serv_params = sockaddr_in($port, $dest_ip);

	socket(my $s, &AF_INET, &SOCK_STREAM, 0) or die "socket: $!";
	connect($s, $dest_serv_params) or die "connect: $!";

	my $ssl = Net::SSLeay::new($ctx) or die("Failed to create SSL $!");
	Net::SSLeay::set_fd($ssl, fileno($s));
	Net::SSLeay::connect($ssl) or die("ssl connect");
	return ($s, $ssl);
}

###############################################################################
