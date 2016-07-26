#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with ssl.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2/)
	->has_daemon('openssl')->plan(1);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2 ssl;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

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

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config '$d/openssl.conf' -subj '/CN=$name/' "
		. "-out '$d/$name.crt' -keyout '$d/$name.key' "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('tbig.html',
	join('', map { sprintf "XX%06dXX", $_ } (1 .. 500000)));

open OLDERR, ">&", \*STDERR; close STDERR;
$t->run();
open STDERR, ">&", \*OLDERR;

###############################################################################

# client cancels 2nd stream after HEADERS has been created
# while some unsent data was left in the SSL buffer
# HEADERS frame may stuck in SSL buffer and won't be sent producing alert

SKIP: {
my $s = getconn(port(0));
skip 'OpenSSL ALPN/NPN support required', 1 unless defined $s;

ok($s, 'ssl connection');

$t->todo_alerts() unless $t->has_version('1.11.3');

my $sid = $s->new_stream({ path => '/tbig.html' });

select undef, undef, undef, 0.2;
$s->h2_rst($sid, 8);

$sid = $s->new_stream({ path => '/tbig.html' });

select undef, undef, undef, 0.2;
$s->h2_rst($sid, 8);

$t->stop();

}

###############################################################################

sub getconn {
	my ($port) = @_;
	my $s;

	eval {
		IO::Socket::SSL->can_alpn() or die;
		$s = Test::Nginx::HTTP2->new($port, SSL => 1, alpn => 'h2');
	};

	return $s if defined $s;

	eval {
		IO::Socket::SSL->can_npn() or die;
		$s = Test::Nginx::HTTP2->new($port, SSL => 1, npn => 'h2');
	};

	return $s;
}

###############################################################################
