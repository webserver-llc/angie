#!/usr/bin/perl

# (C) Maxim Dounin

# Test for http backend not closing connection properly after sending full
# reply.  This is in fact backend bug, but it seems common, and anyway
# correct handling is required to support persistent connections.

###############################################################################

use warnings;
use strict;

use Test::More tests => 1;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new();

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    server {
        listen       localhost:8080;
        server_name  localhost;

        location / {
            proxy_pass http://localhost:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_noclose_daemon);
$t->run();

###############################################################################

TODO: {
local $TODO = 'not fixed yet, submit patches';

my $t1 = http_request('/');
like($t1, qr/TEST-OK-IF-YOU-SEE-THIS/, 'request to bad backend');

}

###############################################################################

sub http_request {
	my ($url) = @_;
	my $r = http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close

EOF
}

sub http_noclose_daemon {
	my $server = IO::Socket::INET->new(
        	Proto => 'tcp',
        	LocalPort => 8081,
        	Listen => 5,
        	Reuse => 1
	)
        	or die "Can't create listening socket: $!\n";

	while (my $client = $server->accept()) {
        	$client->autoflush(1);

        	while (<$client>) {
                	last if (/^\x0d?\x0a?$/);
        	}

        	print $client <<'EOF';
HTTP/1.1 200 OK
Content-Length: 24
Connection: close

TEST-OK-IF-YOU-SEE-THIS
EOF
        	sleep 2;
        	close $client;
	}
}

###############################################################################
