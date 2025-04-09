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

use IPC::Open3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $openssl = $ENV{'TEST_ANGIE_OPENSSL_BINARY'} || 'openssl';

my $t = Test::Nginx->new()->has(qw/stream stream_ssl socket_ssl/)
	->has(qw/http rewrite/)
	->has_daemon($openssl);

plan(skip_all => 'no TLSv1.3 sessions in LibreSSL')
	if $t->has_module('LibreSSL');

$t->plan(6)->write_file_expand('nginx.conf', <<'EOF');

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

        ssl_early_data on;

        access_log %%TESTDIR%%/s1.log ed;
    }

    # testcase 2: disabled early data
    server {
        listen      127.0.0.1:8083 ssl;
        proxy_pass  127.0.0.1:8081;

        ssl_early_data off;
        access_log %%TESTDIR%%/s2.log ed;
    }
}

# real HTTP block to have server that really processes requests
http {

    %%TEST_GLOBALS_HTTP%%

    access_log %%TESTDIR%%/back.log;

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

$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

my $req_early = "GET /early HTTP/1.0\r\n\r\n";
my $req_regular = "GET /regular HTTP/1.0\r\n\r\n";
$t->write_file("req.txt", $req_early);

# 1st request: establish session and save it
like(early_get(port(8082), "-no_ticket -sess_out $sess1", "$req_regular"), qr/REGULAR/, 'initial response from 8082');
# 2nd request: resume session and pass request via early data
like(early_get(port(8082), "-early_data $early -sess_in $sess1", ""), qr/EARLY/, 'resume and early data 8082');

# 3rd request: establish session to server with early_data disabled
like(early_get(port(8083), "-no_ticket -sess_out $sess2", "$req_regular"), qr/REGULAR/, 'initial response from 8083');
# 4th request: try to resume session and use early data - shoudl not succeed
like(early_get(port(8083), "-early_data $early -sess_in $sess2", "$req_regular"), qr/REGULAR/, 'response from 8083 no early');

# now verify all other logs
$t->stop();

# check that we have variables with proper values logged
like($t->read_file('s1.log'), qr/r/, 'session reused in test1');
like($t->read_file('s2.log'), qr/r/, 'session reused in test2');


###############################################################################

sub early_get {
	my ($p, $args, $payload) = @_;
	my $r;

	my $pid = open3(my $ssl_in, my $ssl_out, my $ssl_err,
		"$openssl s_client -connect localhost:$p -quiet -ign_eof " . $args)
    or die "Can't run $openssl: $!";

	print $ssl_in $payload ;
	while (<$ssl_out>) { $r .= $_ }

	waitpid($pid, 0);

	return $r;
}

###############################################################################
