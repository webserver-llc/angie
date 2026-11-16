#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for stream ssl with early data.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;
use Test::Utils qw/get_json/;

use IPC::Open3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_ssl socket_ssl/)
	->has(qw/http http_api rewrite/)
	->has_daemon('openssl');

plan(skip_all => 'no TLSv1.3 sessions in LibreSSL')
	if $t->has_module('LibreSSL');

$t->plan(12)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    # early data happens at resumed ssl connection, so we need sessions
    ssl_session_cache    shared:SSL:1m;


    # log connection-related things to check later
    log_format  ed  $ssl_session_reused;

    # testcase 1: enabled early data
    server {
        listen      127.0.0.1:8082 ssl;
        proxy_pass  127.0.0.1:8081;
        status_zone ssl_early_data_on;

        ssl_early_data on;

        access_log %%TESTDIR%%/s1.log ed;
    }

    # testcase 2: disabled early data
    server {
        listen      127.0.0.1:8083 ssl;
        proxy_pass  127.0.0.1:8081;
        status_zone ssl_early_data_off;

        ssl_early_data off;
        access_log %%TESTDIR%%/s2.log ed;
    }
}

# real HTTP block to have server that really processes requests
http {

    %%TEST_GLOBALS_HTTP%%

    access_log %%TESTDIR%%/back.log;

    server {
        listen      127.0.0.1:8080;

        location /status/ {
            api /status/;
        }
    }

    server {
        listen 127.0.0.1:8081;

        # default location, should never see it
        location / {
            return 200 "DFLT\n";
        }

        # if we are here, we are processing HTTP request from early data
        location /early {
            return 200 "EARLY\n";
        }

        # if we are here, we are processing request passed as usually
        location /regular {
            return 200 "REGULAR\n";
        }
    }
}

EOF


my $d = $t->testdir();

# saved sessions to resume for both servers
my $sess1 = "$d/session1.txt";
my $sess2 = "$d/session2.txt";
# request used as early data is saved in file for openssl s_client
my $early = "$d/req.txt";

# generate certificates from stream ssl server
$t->prepare_ssl();

$t->run();

my ($p1, $p2, $p3) = (port(8081), port(8082), port(8083));

$t->waitforsocket("127.0.0.1:$p1");
$t->waitforsocket("127.0.0.1:$p2");
$t->waitforsocket("127.0.0.1:$p3");

###############################################################################

my $req_early = "GET /early HTTP/1.0\r\n\r\n";
my $req_regular = "GET /regular HTTP/1.0\r\n\r\n";
$t->write_file("req.txt", $req_early);

# server 1: ssl_early_data on

my $before1 = get_ssl_stats('ssl_early_data_on');

# 1st request: establish session and save it
like(early_get($p2, "-no_ticket -sess_out $sess1", $req_regular),
	qr/REGULAR/, "initial response from $p2");
# 2nd request: resume session and pass request via early data
like(early_get($p2, "-early_data $early -sess_in $sess1", ""),
	qr/EARLY/, "resume and early data $p2");

my $after1 = get_ssl_stats('ssl_early_data_on');

is($after1->{handshaked} - $before1->{handshaked}, 2,
	'stats: 2 successful handshakes counted (on)');
is($after1->{reuses} - $before1->{reuses}, 1,
	'stats: 1 session reuse counted (on, via early data)');
is($after1->{failed}, $before1->{failed}, 'stats: no failed handshakes (on)');

# server 2: ssl_early_data off

my $before2 = get_ssl_stats('ssl_early_data_off');

# 3rd request: establish session to server with early_data disabled
like(early_get($p3, "-no_ticket -sess_out $sess2", $req_regular),
	qr/REGULAR/, "initial response from $p3");
# 4th request: try to resume session and use early data - should not succeed
like(early_get($p3, "-early_data $early -sess_in $sess2", $req_regular),
	qr/REGULAR/, "response from $p3 no early");

my $after2 = get_ssl_stats('ssl_early_data_off');

is($after2->{handshaked} - $before2->{handshaked}, 2,
	'stats: 2 successful handshakes counted (off)');
is($after2->{reuses} - $before2->{reuses}, 1,
	'stats: 1 session reuse counted (off, via regular 1-RTT)');
is($after2->{failed}, $before2->{failed}, 'stats: no failed handshakes (off)');

# now verify all other logs
$t->stop();

# check that we have variables with proper values logged
like($t->read_file('s1.log'), qr/^r$/m, 'session reused in test1');
like($t->read_file('s2.log'), qr/^r$/m, 'session reused in test2');

###############################################################################

sub early_get {
	my ($p, $args, $payload) = @_;

	my $pid =
		open3(my $ssl_in, my $ssl_out, my $ssl_err,
			"openssl s_client -connect localhost:$p -quiet -ign_eof $args")
		or die "Can't run openssl: $!";

	print $ssl_in $payload;

	my $r;
	while (<$ssl_out>) { $r .= $_ }

	waitpid($pid, 0);

	return $r;
}

sub get_ssl_stats {
	my ($zone) = @_;
	return get_json("/status/stream/server_zones/$zone/ssl");
}

###############################################################################
