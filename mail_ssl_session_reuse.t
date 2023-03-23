#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Maxim Dounin
# (C) Nginx, Inc.

# Tests for mail ssl module, session reuse.

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
	require Net::SSLeay;
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
};
plan(skip_all => 'Net::SSLeay not installed') if $@;

my $t = Test::Nginx->new()->has(qw/mail mail_ssl imap/)
	->has_daemon('openssl')->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  http://127.0.0.1:8080;

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    server {
        listen    127.0.0.1:8993 ssl;
        protocol  imap;
    }

    server {
        listen    127.0.0.1:8994 ssl;
        protocol  imap;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets on;
    }

    server {
        listen    127.0.0.1:8995 ssl;
        protocol  imap;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;
    }

    server {
        listen    127.0.0.1:8996 ssl;
        protocol  imap;

        ssl_session_cache builtin;
        ssl_session_tickets off;
    }

    server {
        listen    127.0.0.1:8997 ssl;
        protocol  imap;

        ssl_session_cache builtin:1000;
        ssl_session_tickets off;
    }

    server {
        listen    127.0.0.1:8998 ssl;
        protocol  imap;

        ssl_session_cache none;
        ssl_session_tickets off;
    }

    server {
        listen    127.0.0.1:8999 ssl;
        protocol  imap;

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

$t->run();

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

is(test_reuse(8993), 1, 'tickets reused');
is(test_reuse(8994), 1, 'tickets and cache reused');
is(test_reuse(8995), 1, 'cache shared reused');
is(test_reuse(8996), 1, 'cache builtin reused');
is(test_reuse(8997), 1, 'cache builtin size reused');
is(test_reuse(8998), 0, 'cache none not reused');
is(test_reuse(8999), 0, 'cache off not reused');

###############################################################################

sub test_reuse {
	my ($port) = @_;
	my ($s, $ssl) = get_ssl_socket($port);
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
	Net::SSLeay::connect($ssl) == 1 or return;
	return ($s, $ssl);
}

###############################################################################
