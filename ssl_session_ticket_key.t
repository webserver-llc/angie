#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for rotation of SSL session ticket keys.

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

eval {
	require Net::SSLeay; die if $Net::SSLeay::VERSION < 1.86;
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
};
plan(skip_all => 'Net::SSLeay version => 1.86 required') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)->has_daemon('openssl')
	->plan(2)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 2;
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

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();

###############################################################################

# the test uses multiple worker processes to check shared tickey key rotation
#
# before 1.23.2, any test can fail depending on which worker served connection:
# the 1st test fails if served by another worker, because keys aren't shared
# the 2nd test fails if served by the same worker due to the lack of rotation
#
# with a single worker process it is only the 2nd test that fails

local $TODO = 'not yet' unless $t->has_version('1.23.2');

my $key = get_ticket_key_name();

select undef, undef, undef, 0.5;
is(get_ticket_key_name(), $key, 'ticket key match');

select undef, undef, undef, 2.5;
cmp_ok(get_ticket_key_name(), 'ne', $key, 'ticket key next');

###############################################################################

sub get_ticket_key_name {
	my $ses = get_ssl_session();
	my $asn = Net::SSLeay::i2d_SSL_SESSION($ses);
	my $any = qr/[\x00-\xff]/;
next:
	# tag(10) | len{2} | OCTETSTRING(4) | len{2} | ticket(key_name|..)
	$asn =~ /\xaa\x81($any)\x04\x81($any)($any{16})/g;
	return if !defined $3;
	goto next if unpack("C", $1) - unpack("C", $2) != 3;
	my $key = unpack "H*", $3;
	Test::Nginx::log_core('||', "ticket key: $key");
	return $key;
}

sub get_ssl_session {
	my ($s, $ssl) = get_ssl_socket();

	Net::SSLeay::write($ssl, <<EOF);
GET / HTTP/1.0
Host: localhost

EOF
	Net::SSLeay::read($ssl);
	Net::SSLeay::get_session($ssl);
}

sub get_ssl_socket {
	my $s = IO::Socket::INET->new('127.0.0.1:' . port(8080));
	my $ctx = Net::SSLeay::CTX_new() or die("Failed to create SSL_CTX $!");
	my $ssl = Net::SSLeay::new($ctx) or die("Failed to create SSL $!");
	Net::SSLeay::set_fd($ssl, fileno($s));
	Net::SSLeay::connect($ssl) or die("ssl connect");
	return ($s, $ssl);
}

###############################################################################
