#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Stream tests for proxy to ssl backend, backend certificate verification.

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

my $t = Test::Nginx->new()->has(qw/stream stream_ssl/)->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF')->plan(6);

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    proxy_ssl on;
    proxy_ssl_verify on;

    server {
        listen      127.0.0.1:%%PORT_0%%;
        proxy_pass  127.0.0.1:%%PORT_6%%;

        proxy_ssl_name example.com;
        proxy_ssl_trusted_certificate 1.example.com.crt;
    }

    server {
        listen      127.0.0.1:%%PORT_1%%;
        proxy_pass  127.0.0.1:%%PORT_6%%;

        proxy_ssl_name foo.example.com;
        proxy_ssl_trusted_certificate 1.example.com.crt;
    }

    server {
        listen      127.0.0.1:%%PORT_2%%;
        proxy_pass  127.0.0.1:%%PORT_6%%;

        proxy_ssl_name no.match.example.com;
        proxy_ssl_trusted_certificate 1.example.com.crt;
    }

    server {
        listen      127.0.0.1:%%PORT_3%%;
        proxy_pass  127.0.0.1:%%PORT_7%%;

        proxy_ssl_name 2.example.com;
        proxy_ssl_trusted_certificate 2.example.com.crt;
    }

    server {
        listen      127.0.0.1:%%PORT_4%%;
        proxy_pass  127.0.0.1:%%PORT_7%%;

        proxy_ssl_name bad.example.com;
        proxy_ssl_trusted_certificate 2.example.com.crt;
    }

    server {
        listen      127.0.0.1:%%PORT_5%%;
        proxy_pass  127.0.0.1:%%PORT_7%%;

        proxy_ssl_trusted_certificate 1.example.com.crt;
        proxy_ssl_session_reuse off;
    }

    server {
        listen      127.0.0.1:%%PORT_6%% ssl;
        proxy_pass  127.0.0.1:%%PORT_8%%;
        proxy_ssl   off;

        ssl_certificate 1.example.com.crt;
        ssl_certificate_key 1.example.com.key;
    }

    server {
        listen      127.0.0.1:%%PORT_7%% ssl;
        proxy_pass  127.0.0.1:%%PORT_8%%;
        proxy_ssl   off;

        ssl_certificate 2.example.com.crt;
        ssl_certificate_key 2.example.com.key;
    }
}

EOF

$t->write_file('openssl.1.example.com.conf', <<EOF);
[ req ]
prompt = no
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
x509_extensions = v3_req

[ req_distinguished_name ]
commonName=no.match.example.com

[ v3_req ]
subjectAltName = DNS:example.com,DNS:*.example.com
EOF

$t->write_file('openssl.2.example.com.conf', <<EOF);
[ req ]
prompt = no
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
commonName=2.example.com
EOF

my $d = $t->testdir();

foreach my $name ('1.example.com', '2.example.com') {
	system('openssl req -x509 -new '
		. "-config '$d/openssl.$name.conf' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('index.html', '');

$t->run_daemon(\&http_daemon);
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8));

###############################################################################

# subjectAltName

like(get('/', '127.0.0.1:' . port(0)), qr/200 OK/, 'verify');
like(get('/', '127.0.0.1:' . port(1)), qr/200 OK/, 'verify wildcard');
unlike(get('/', '127.0.0.1:' . port(2)), qr/200 OK/, 'verify fail');

# commonName

like(get('/', '127.0.0.1:' . port(3)), qr/200 OK/, 'verify cn');
unlike(get('/', '127.0.0.1:' . port(4)), qr/200 OK/, 'verify cn fail');

# untrusted

unlike(get('/', '127.0.0.1:' . port(5)), qr/200 OK/, 'untrusted');

###############################################################################

sub get {
	my ($uri, $peer) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => $peer
	)
		or die "Can't connect to nginx: $!\n";

	my $r = http_get($uri, socket => $s);
	return defined $r ? $r : '';
}

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (<$client>) {
			last if (/^\x0d?\x0a?$/);
		}

		print $client <<EOF;
HTTP/1.1 200 OK
Connection: close

EOF

		close $client;
	}
}

###############################################################################
