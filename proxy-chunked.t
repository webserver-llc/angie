#!/usr/bin/perl

# (C) Maxim Dounin

# Test for http backend returning response with Transfer-Encoding: chunked.

# Since nginx uses HTTP/1.0 in requests to backend it's backend bug, but we
# want to handle this gracefully.  And anyway chunked support will be required
# for HTTP/1.1 backend connections.

###############################################################################

use warnings;
use strict;

use Test::More tests => 1;

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
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_chunked_daemon);
$t->run();

###############################################################################

{
local $TODO = 'not yet';

like(http_get('/'), qr/\x0d\x0aSEE-THIS$/s, 'chunked');
}

###############################################################################

sub http_chunked_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:8081',
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
Connection: close
Transfer-Encoding: chunked

9
SEE-THIS

0

EOF

		close $client;
	}
}

###############################################################################
