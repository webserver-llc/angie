#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Maxim Dounin
# (C) Nginx, Inc.

# Tests for stream ssl module, session reuse.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ $CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

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

my $t = Test::Nginx->new()->has(qw/stream stream_ssl/)->has_daemon('openssl');

$t->plan(7)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    server {
        listen      127.0.0.1:8443 ssl;
        proxy_pass  127.0.0.1:8081;
    }

    server {
        listen      127.0.0.1:8444 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets on;
    }

    server {
        listen      127.0.0.1:8445 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;
    }

    server {
        listen      127.0.0.1:8446 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache builtin;
        ssl_session_tickets off;
    }

    server {
        listen      127.0.0.1:8447 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache builtin:1000;
        ssl_session_tickets off;
    }

    server {
        listen      127.0.0.1:8448 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache none;
        ssl_session_tickets off;
    }

    server {
        listen      127.0.0.1:8449 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_session_cache off;
        ssl_session_tickets off;
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

my $ctx = Net::SSLeay::CTX_new() or die("Failed to create SSL_CTX $!");

$t->run_daemon(\&http_daemon);

$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# session reuse:
#
# - only tickets, the default
# - tickets and shared cache, should work always
# - only shared cache
# - only builtin cache
# - only builtin cache with explicitly configured size
# - only cache none
# - only cache off

is(test_reuse(8443), 1, 'tickets reused');
is(test_reuse(8444), 1, 'tickets and cache reused');
is(test_reuse(8445), 1, 'cache shared reused');
is(test_reuse(8446), 1, 'cache builtin reused');
is(test_reuse(8447), 1, 'cache builtin size reused');
is(test_reuse(8448), 0, 'cache none not reused');
is(test_reuse(8449), 0, 'cache off not reused');

###############################################################################

sub test_reuse {
	my ($port) = @_;
	my ($s, $ssl) = get_ssl_socket($port);
	Net::SSLeay::write($ssl, "GET / HTTP/1.0$CRLF$CRLF");
	Net::SSLeay::read($ssl);
	my $ses = Net::SSLeay::get_session($ssl);
	($s, $ssl) = get_ssl_socket($port, $ses);
	return Net::SSLeay::session_reused($ssl);
}

sub get_ssl_socket {
	my ($port, $ses) = @_;

	my $s = IO::Socket::INET->new('127.0.0.1:' . port($port));
	my $ssl = Net::SSLeay::new($ctx) or die("Failed to create SSL $!");
	Net::SSLeay::set_session($ssl, $ses) if defined $ses;
	Net::SSLeay::set_fd($ssl, fileno($s));
	Net::SSLeay::connect($ssl) or die("ssl connect");
	return ($s, $ssl);
}

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
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
