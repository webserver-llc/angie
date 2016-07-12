#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module with multiple certificates.

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
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_dhparam dhparam.pem;

    ssl_certificate_key rsa.key;
    ssl_certificate rsa.crt;

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_certificate_key dsa.key;
        ssl_certificate dsa.crt;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;

        ssl_certificate_key rsa.key;
        ssl_certificate rsa.crt;
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

system("openssl dhparam -dsaparam 1024 -out '$d/dhparam.pem' "
	. ">>$d/openssl.out 2>&1") == 0 or die "Can't create DH param: $!\n";
system("openssl genrsa -out '$d/rsa.key' >>$d/openssl.out 2>&1") == 0
        or die "Can't create RSA pem: $!\n";
system("openssl dsaparam -genkey 1024 -out '$d/dsa.key' >>$d/openssl 2>&1") == 0
	or die "Can't create DSA pem: $!\n";

foreach my $name ('dsa', 'rsa') {
	system("openssl req -x509 -new -key '$d/$name.key' "
		. "-config '$d/openssl.conf' -subj '/CN=$name/' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->try_run('no multiple certificates')->plan(2);

###############################################################################

like(get_cert('RSA'), qr/CN=rsa/, 'ssl cert RSA');
like(get_cert('DSS'), qr/CN=dsa/, 'ssl cert DSA');

###############################################################################

sub get_cert {
	my ($ciphers) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(2);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => port(8080),
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_cipher_list => $ciphers,
			SSL_error_trap => sub { die $_[1] }
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	my $cipher = $s->get_cipher();

	Test::Nginx::log_core('||', "cipher: $cipher");

	return $s->dump_peer_certificate;
}

###############################################################################
