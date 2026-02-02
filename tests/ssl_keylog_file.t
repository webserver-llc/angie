#!/usr/bin/perl

# (C) 2026 Web Server LLC

# ssl_keylog_file directive tests

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/trim/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http stream proxy http_ssl stream_ssl rewrite/)
	->has_daemon('openssl')->plan(21);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /https {
            proxy_pass https://127.0.0.1:8081;
            proxy_ssl_keylog_file %%TESTDIR%%/https_proxy.keylog;
        }

        location /https12 {
            proxy_pass https://127.0.0.1:8083;
        }

        location /stream {
            proxy_pass https://127.0.0.1:8082;
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  ssl_localhost;

        ssl_keylog_file %%TESTDIR%%/https.keylog;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            return 200 "PROXIED13";
        }
    }

    server {
        listen       127.0.0.1:8083 ssl;
        server_name  tls12;

        ssl_keylog_file %%TESTDIR%%/https12.keylog;

        ssl_protocols TLSv1.2;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            return 200 "PROXIED12";
        }
    }

}

stream {
    server {
        listen       127.0.0.1:8082 ssl;
        server_name  stream_localhost;

        ssl_keylog_file %%TESTDIR%%/stream.keylog;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        proxy_pass 127.0.0.1:8081;
        proxy_ssl on;

        proxy_ssl_keylog_file %%TESTDIR%%/stream_proxy.keylog;
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/https'), qr/PROXIED13/, "https query");
like(http_get('/stream'), qr/PROXIED13/, "stream https query");

like(http_get('/https12'), qr/PROXIED12/, "https12 query");

$t->stop();

my @files12 = ('https12.keylog');

my @files13 = ('https.keylog', 'stream.keylog', 'https_proxy.keylog',
	'stream_proxy.keylog');

TODO: {

	local $TODO = 'LibreSSL does not support keylog'
		if $t->has_module('LibreSSL');

	for my $file (@files12) {
		check_file($t, $file);
		check_secret($t, $file, 'CLIENT_RANDOM', 'secret in TLS 1.2');
	}

	for my $file (@files13) {

		check_file($t, $file);

		check_secret($t, $file, 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
			'server h/s secret in TLS 1.3');
		check_secret($t, $file, 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
			'client h/s secret in TLS 1.3');
		check_secret($t, $file, 'EXPORTER_SECRET',
			'exporter secret in TLS 1.3');
	}

}

###############################################################################

sub check_secret {
	my ($t, $fname, $pattern, $msg) = @_;

	my $n = $t->find_in_file($fname, qr/$pattern/);
	is($n > 0, 1, "$msg found in $fname");
}

# verifies that keys format is as expected according to
# https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
sub check_file {
	my ($t, $fname) = @_;

	my $d = $t->testdir();

	my $lines = get_lines("$d/$fname");

	if (@$lines == 0) {
		fail("file $fname has some lines");
		return;
	}

	my $n = 1;

	for my $line (@$lines) {

		if ($line =~ /^#.*/) {
			# file may contain comments
			next;
		}
		if ($line =~ /^$/) {
			# empty lines may present
			next;
		}

		# random and secret is hex (lower or upper)
		my ($label, $client_random, $secret) = $line
			=~ /^(\w+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)$/;

		if (!defined($label)) {
			fail("missing label at $fname:$n\n");
			return;
		}

		if (!defined($client_random)) {
			fail("missing client random at $fname:$n\n");
			return;
		}

		if (!defined($secret)) {
			fail("missing secret at $fname:$n\n");
			return;
		}

		$n++;
	}

	pass("file $fname has correct format");
}

sub get_lines {
	my ($file) = @_;

	my $fh;

	open $fh, '<', $file or do {
		warn "Cannot open $file: $!";
		return [];
	};

	my @lines;
	for my $line (<$fh>) {
		$line = trim($line);
		push @lines, $line;
	}

	return \@lines;
}

