#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for HTTP ssl with early data (non-QUIC, TLS over TCP).

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use IPC::Open3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite/)
	->has_daemon('openssl');

plan(skip_all => 'no TLSv1.3 sessions in LibreSSL')
	if $t->has_module('LibreSSL');

$t->plan(12)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    # early data happens at resumed connection, so we need sessions
    ssl_session_cache shared:SSL:1m;

    add_header X-Session $ssl_session_reused always;
    add_header X-Early   $ssl_early_data     always;

    # testcase 1: enabled early data
    server {
        listen      127.0.0.1:8081 ssl;
        server_name localhost;

        ssl_early_data on;

        location / { return 200 "REGULAR\n"; }
    }

    # testcase 2: disabled early data
    server {
        listen      127.0.0.1:8082 ssl;
        server_name localhost;

        ssl_early_data off;

        location / { return 200 "REGULAR\n"; }
    }
}

EOF


my $d = $t->testdir();

my $sess1 = "$d/session1.txt";
my $sess2 = "$d/session2.txt";
my $req_file = "$d/req.txt";

$t->prepare_ssl();
$t->run();

my ($p1, $p2) = (port(8081), port(8082));

$t->waitforsocket("127.0.0.1:$p1");
$t->waitforsocket("127.0.0.1:$p2");

###############################################################################

my $req = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
$t->write_file("req.txt", $req);

# server 1: ssl_early_data on

# first connection: establish session (no early data)
my $r1 = early_get($p1, "-no_ticket -sess_out $sess1", $req);
like($r1, qr/200 OK/, "initial handshake on $p1");
like($r1, qr/^x-session: \.\s?$/im, "new session (not reused) on $p1");
unlike($r1, qr/^x-early:/im, "no x-early header on initial handshake $p1");

# second connection: resume with early data
my $r2 = early_get($p1, "-early_data $req_file -sess_in $sess1", "");
like($r2, qr/200 OK/, "resumed handshake with early data on $p1");
like($r2, qr/^x-session: r\s?$/im, "session reused on $p1");

TODO: {
	local $TODO = 'race: SSL_is_init_finished() may be true by response time';
	like($r2, qr/^x-early: 1/im, "x-early header set for $p1");
}

# server 2: ssl_early_data off

my $r3 = early_get($p2, "-no_ticket -sess_out $sess2", $req);
like($r3, qr/200 OK/, "initial handshake on $p2");
like($r3, qr/^x-session: \.\s?$/im, "new session (not reused) on $p2");
unlike($r3, qr/^x-early:/im, "no x-early header on initial handshake $p2");

my $r4 = early_get($p2, "-early_data $req_file -sess_in $sess2", $req);
like($r4, qr/200 OK/, "resumed handshake, early data ignored on $p2");
like($r4, qr/^x-session: r\s?$/im, "session reused (via regular 1-RTT) on $p2");
unlike($r4, qr/^x-early: 1/im, "x-early header not set for $p2");

###############################################################################

sub early_get {
	my ($p, $args, $payload) = @_;

	my $cmd = "openssl s_client -connect localhost:$p -quiet"
		. " -servername localhost -ign_eof $args";
	my $pid = open3(my $ssl_in, my $ssl_out, my $ssl_err, $cmd)
		or die "Can't run openssl: $!";

	print $ssl_in $payload;

	my $r;
	while (<$ssl_out>) { $r .= $_ }

	waitpid($pid, 0);

	return $r;
}

###############################################################################
