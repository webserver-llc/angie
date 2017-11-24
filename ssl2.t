#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for http ssl module.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite/)
	->has_daemon('openssl');

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

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        location /ciphers {
            return 200 "body $ssl_ciphers";
        }
        location /issuer {
            return 200 "body $ssl_client_i_dn_legacy";
        }
        location /subject {
            return 200 "body $ssl_client_s_dn_legacy";
        }
        location /time {
            return 200 "body $ssl_client_v_start!$ssl_client_v_end!$ssl_client_v_remain";
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

$t->write_file('ca.conf', <<EOF);
[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $d
database = $d/certindex
default_md = sha1
policy = myca_policy
serial = $d/certserial
default_days = 3

[ myca_policy ]
commonName = supplied
EOF

$t->write_file('certserial', '1000');
$t->write_file('certindex', '');

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=issuer/ "
	. "-out $d/issuer.crt -keyout $d/issuer.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for issuer: $!\n";

system("openssl req -new "
	. "-config $d/openssl.conf -subj /CN=subject/ "
	. "-out $d/subject.csr -keyout $d/subject.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for subject: $!\n";

system("openssl ca -batch -config $d/ca.conf "
	. "-keyfile $d/issuer.key -cert $d/issuer.crt "
	. "-subj /CN=subject/ -in $d/subject.csr -out $d/subject.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign certificate for subject: $!\n";

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run()->plan(4);

###############################################################################

like(get('/ciphers'), qr/^body [:\w-]+$/m, 'ciphers');
like(get('/issuer'), qr!^body /CN=issuer$!m, 'issuer');
like(get('/subject'), qr!^body /CN=subject$!m, 'subject');
like(get('/time'), qr/^body [:\s\w]+![:\s\w]+![23]$/m, 'time');

###############################################################################

sub get {
	my ($uri) = @_;
	my $s = get_ssl_socket() or return;
	http_get($uri, socket => $s);
}

sub get_ssl_socket {
	my (%extra) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(2);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => port(8080),
			SSL_cert_file => "$d/subject.crt",
			SSL_key_file => "$d/subject.key",
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_error_trap => sub { die $_[1] },
			%extra
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

###############################################################################
