#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, certificate compression.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl openssl:3.2 socket_ssl/)
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
    ssl_certificate_compression on;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_certificate_compression off;

        add_header X-Protocol $ssl_protocol;
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;
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

$t->write_file('index.html', '');

$t->try_run('no ssl_certificate_compression');

plan(skip_all => 'no ssl_certificate_compression support')
	if $t->read_file('error.log') =~ /SSL_CTX_compress_certs/;
plan(skip_all => 'no set_msg_callback, old IO::Socket::SSL')
	if $IO::Socket::SSL::VERSION < 2.081;

$t->plan(4);

###############################################################################

# handshake type:
#
# certificate(11)
# compressed_certificate(25)

my $cert_ht;
my $has_zlib = 0;

like(get('/', 8443), qr/200 OK/, 'request');
is($cert_ht, 11, 'cert compression off');

# only supported with TLS 1.3 and newer

my $exp = 25;
$exp = 11 unless test_tls13();

like(get('/', 8444), qr/200 OK/, 'request 2');
is($cert_ht, $exp, 'cert compression on');

###############################################################################

sub test_tls13 {
	http_get('/', SSL => 1) =~ /TLSv1.3/ && $has_zlib;
}

sub get {
	my ($uri, $port) = @_;
	my $s = get_ssl_socket($port) or return;
	http_get($uri, socket => $s);
}

sub get_ssl_socket {
	my ($port) = @_;
	my $s = http(
		'', PeerAddr => '127.0.0.1:' . port($port), start => 1,
		SSL => 1,
		SSL_startHandshake => 0,
	);
	$s->set_msg_callback(\&cb, 0, 0);
	$s->connect_SSL();
	http('', start => 1, socket => $s);
}

sub cb {
	my ($s, $wr, $ssl_ver, $ct, $buf) = @_;

	if ($wr == 1 && $ssl_ver == 0x0304 && $ct == 22) {

		return if $has_zlib;
		return unless unpack("C", $buf) == 1;

		# TLSv1.3 ClientHello

		my $n = 6 + 32;
		my $slen = unpack("C", substr($buf, $n));
		$n += 1 + $slen;
		my $clen = unpack("n", substr($buf, $n));
		$n += 2 + $clen + 2 + 2;

		while ($n < length($buf)) {

			my $ext = unpack("n", substr($buf, $n));
			my $len = unpack("n", substr($buf, $n + 2));

			if ($ext != 27) {
				$n += 4 + $len;
				next;
			}

			# compress_certificate(27)

			$n += 4;
			for (my $k = 1; $k < $len; $k += 2) {
				my $algo = unpack("n", substr($buf, $n + $k));
				$has_zlib = 1 if $algo == 1;
				last;
			}

			last;
		}
	}

	if ($wr == 0 && $ct == 22) {

		my $ht = unpack("C", $buf);
		return unless $ht == 11 || $ht == 25;

		log_in("ssl cert handshake type: " . $ht);
		$cert_ht = $ht;
	}
}

###############################################################################
