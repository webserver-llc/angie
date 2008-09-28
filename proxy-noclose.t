#!/usr/bin/perl

# (C) Maxim Dounin

# Test for http backend not closing connection properly after sending full
# reply.  This is in fact backend bug, but it seems common, and anyway
# correct handling is required to support persistent connections.

###############################################################################

use warnings;
use strict;

use Test::More tests => 2;

use IO::Select;

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

like(http_request('/'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'request to bad backend');
like(http_request('/multi'), qr/AND-THIS/, 'bad backend - multiple packets');

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

		my $multi = 0;

        	while (<$client>) {
			$multi = 1 if /multi/;
                	last if (/^\x0d?\x0a?$/);
        	}

		my $length = $multi ? 32 : 24;

        	print $client <<"EOF";
HTTP/1.1 200 OK
Content-Length: $length
Connection: close

TEST-OK-IF-YOU-SEE-THIS
EOF

		if ($multi) {
			select undef, undef, undef, 0.1;
			print $client 'AND-THIS';
		}

		my $select = IO::Select->new($client);
        	$select->can_read(2);
        	close $client;
	}
}

###############################################################################
