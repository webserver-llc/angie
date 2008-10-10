#!/usr/bin/perl

# (C) Maxim Dounin

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has('mail', plan => 2)
	->write_file_expand('nginx.conf', <<'EOF')->run();

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

mail {
    proxy_pass_error_message  on;
    auth_http  http://localhost:8080/mail/auth;
    xclient    off;

    server {
        listen     localhost:8025;
        protocol   smtp;
        smtp_greeting_delay  100ms;
    }
}

EOF

###############################################################################

# With smtp_greeting_delay session expected to be closed after first error
# message if client sent something before greeting.

my $s = Test::Nginx::SMTP->new();
$s->send('HELO example.com');
$s->check(qr/^5.. /, "command before greeting - session must be rejected");
ok($s->eof(), "session have to be closed");

###############################################################################
