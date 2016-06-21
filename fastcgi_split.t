#!/usr/bin/perl

# (C) Maxim Dounin

# Test for fastcgi backend.
# Incorrect split headers handling after switching to next server,
# as reported by Lucas Molas.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CR LF CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require FCGI; };
plan(skip_all => 'FCGI not installed') if $@;
plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http fastcgi/)->plan(1)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_1%%;
        server 127.0.0.1:%%PORT_2%%;
    }

    server {
        listen       127.0.0.1:%%PORT_0%%;
        server_name  localhost;

        location / {
            fastcgi_pass u;
            fastcgi_param REQUEST_URI $request_uri;
            fastcgi_next_upstream invalid_header;
        }
    }
}

EOF

$t->run_daemon(\&fastcgi_daemon, port(1));
$t->run_daemon(\&fastcgi_daemon, port(2));

$t->run();

$t->waitforsocket('127.0.0.1:' . port(1));
$t->waitforsocket('127.0.0.1:' . port(2));

###############################################################################

like(http_get('/'), qr/^Good: header/ms, 'fastcgi next upstream');

###############################################################################

sub fastcgi_daemon {
	my ($port) = @_;
	my $socket = FCGI::OpenSocket("127.0.0.1:$port", 5);
	my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV,
		$socket);

	my $count;
	while( $request->Accept() >= 0 ) {
		$count++;

		if ($port == port(1)) {
			print 'BAD';
		}
		if ($port == port(2)) {
			print 'Good: header' . CRLF . CRLF;
		}
	}

	FCGI::CloseSocket($socket);
}

###############################################################################
