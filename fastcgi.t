#!/usr/bin/perl

# (C) Maxim Dounin

# Test for fastcgi backend.

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

eval { require FCGI; };
plan(skip_all => 'FCGI not installed') if $@;

my $t = Test::Nginx->new()->plan(3)
	->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

http {
    access_log    off;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       localhost:8080;
        server_name  localhost;

        location / {
            fastcgi_pass 127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon(\&fastcgi_daemon);
$t->run();

###############################################################################

like(http_get('/'), qr/SEE-THIS/, 'fastcgi request');
like(http_get('/redir'), qr/302/, 'fastcgi redirect');
like(http_get('/'), qr/^3$/m, 'fastcgi third request');

###############################################################################

sub fastcgi_daemon {
	my $socket = FCGI::OpenSocket(':8081', 5);
	my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV,
		$socket);

	my $count;
	while( $request->Accept() >= 0 ) {
		print "Location: http://localhost:8080/redirect\r\n";
		print "Content-type: text/html\r\n";
		print "\r\n";
		print "SEE-THIS\n";
		print ++$count;
	}

	FCGI::CloseSocket($socket);
}

###############################################################################
