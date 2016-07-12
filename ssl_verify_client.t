#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, ssl_verify_client.

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

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL->can_client_sni() or die; };
plan(skip_all => 'IO::Socket::SSL with OpenSSL SNI support required') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)
	->has_daemon('openssl')->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    ssl_verify_client optional_no_ca;

    add_header X-Verify $ssl_client_verify;

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_client_certificate client.crt;

        location / { }
    }

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  example.com;

        location / { }
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

foreach my $name ('localhost', 'client') {
	system('openssl req -x509 -new '
		. "-config '$d/openssl.conf' -subj '/CN=$name/' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('t', 'SEE-THIS');

$t->run();

###############################################################################

like(get('localhost'), qr/SUCCESS/, 'success');
like(get('example.com'), qr/FAILED/, 'failed');

# used to be "400 Bad Request" before 654d2dae97d3 (1.11.0)

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.11.0');

like(get('localhost', 'example.com'), qr/421 Misdirected/, 'misdirected');

}

###############################################################################

sub get {
	my ($sni, $host) = @_;
	my $s;

	$host = $sni if !defined $host;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(2);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => port(8080),
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_hostname => $sni,
			SSL_cert_file => "$d/client.crt",
			SSL_key_file => "$d/client.key",
			SSL_error_trap => sub { die $_[1] }
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return http(<<EOF, socket => $s);
GET /t HTTP/1.0
Host: $host

EOF
}

###############################################################################
