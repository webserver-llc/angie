#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log with user-defined tags in mail

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use Sys::Hostname;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap http rewrite/);

$t->plan(11)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%


daemon off;

events {
}

mail {
    proxy_timeout  15s;
    # dead
    auth_http  unix:%%TESTDIR%%/no-such.sock:/mail/auth;

    server {
        error_log_user_tag "srv1";

        listen     127.0.0.1:8143;
        protocol   imap;
    }

    server {
        error_log_user_tag "srv2";

        listen     127.0.0.1:8145;
        protocol   imap;
    }

    server {
        listen     127.0.0.1:8146;
        protocol   imap;
    }

    error_log %%TESTDIR%%/filtered_usertag1.log
              filter=tag:srv1;

    error_log %%TESTDIR%%/filtered_usertag2.log
              filter=tag:srv2;

    error_log %%TESTDIR%%/filtered_usertag-all.log;

}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /xmail/auth {
            add_header Auth-Status OK;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port %%PORT_8144%%;
            add_header Auth-Wait 1;
            return 204;
        }
    }
}

EOF


$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);

$t->waitforsocket('127.0.0.1:' . port(8144));

$t->run();

###############################################################################

my $s;

$s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8143));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered erroron srv1');

$s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8145));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered error on srv2');

$s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8146));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered error on srv3');

$t->stop();

is($t->find_in_file('filtered_usertag-all.log', 'in http auth state'), 3,
	'logged into filtered_usertag-all.log');

is($t->find_in_file('filtered_usertag1.log', 'in http auth state'), 1,
	'single message in filtered_usertag1.log');
is($t->find_in_file('filtered_usertag1.log', qr/login:/), 1,
	'filtered tag1 correct message');

is($t->find_in_file('filtered_usertag2.log', 'in http auth state'), 1,
	'single message in filtered_usertag2.log');
is($t->find_in_file('filtered_usertag2.log', qr/login:/), 1,
	'filtered tag2 correct message');

