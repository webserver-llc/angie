#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx mail module, timeout and proxy_timeout directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap http map rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    proxy_pass_error_message  on;
    timeout        2s;
    proxy_timeout  2s;
    auth_http  http://127.0.0.1:8080/mail/auth;

    server {
        listen     127.0.0.1:8143;
        protocol   imap;
        imap_auth  plain cram-md5 external;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $http_auth_pass $reply {
        secret OK;
        default ERROR;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /mail/auth {
            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port %%PORT_8144%%;
            add_header Auth-Pass "";
            add_header Auth-Wait 1;
            return 204;
        }
    }
}

EOF

$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);
$t->run()->plan(8);

$t->waitforsocket('127.0.0.1:' . port(8144));

###############################################################################

# check proxy timeout

my $s = Test::Nginx::IMAP->new();
$s->read();

# Each of these will wait 1 second before response

$s->send('a01 LOGIN test@example.com bad');
$s->check(qr/^a01 NO/, 'login with bad password');

$s->send('a01 LOGIN test@example.com bad');
$s->check(qr/^a01 NO/, 'login with bad password');

sleep(1);

# Total timeout is 2 seconds, so connection should have been closed

my @ready = $s->can_read(0);
is(scalar @ready, 1, "ready for reading");
ok($s->eof(), "session closed");


$s = Test::Nginx::IMAP->new();
$s->read();

$s->send('a01 LOGIN test@example.com secret');
$s->ok('login');

@ready = $s->can_read(0.1);
is(scalar @ready, 0, "nothing to read after login");

sleep(3);

# Total timeout is 2 seconds, so connection should have been closed

@ready = $s->can_read(0);
is(scalar @ready, 1, "ready for reading");
ok($s->eof(), "session closed");

###############################################################################
