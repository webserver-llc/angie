#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for mail max_commands.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;
use Test::Nginx::POP3;
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap pop3 smtp/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  http://127.0.0.1:8080; # unused

    max_commands 1;

    server {
        listen     127.0.0.1:8143;
        protocol   imap;
    }

    server {
        listen     127.0.0.1:8110;
        protocol   pop3;
    }

    server {
        listen     127.0.0.1:8025;
        protocol   smtp;
    }
}

EOF

$t->try_run('no max_commands')->plan(18);

###############################################################################

# imap

my $s = Test::Nginx::IMAP->new();
$s->read();

$s->send('a01 NOOP');
$s->check(qr/^a01 OK/, 'imap first noop');
$s->send('a02 NOOP');
$s->check(qr/^a02 BAD/, 'imap second noop rejected');
$s->send('a03 NOOP');
$s->check(qr/^$/, 'imap max commands');

$s = Test::Nginx::IMAP->new();
$s->read();

$s->send('a01 NOOP' . CRLF . 'a02 NOOP' . CRLF . 'a03 NOOP');
$s->check(qr/^a01 OK/, 'imap pipelined first noop');
$s->check(qr/^a02 BAD/, 'imap pipelined second noop rejected');
$s->check(qr/^$/, 'imap pipelined max commands');

# pop3

$s = Test::Nginx::POP3->new();
$s->read();

$s->send('NOOP');
$s->check(qr/^\+OK/, 'pop3 first noop');
$s->send('NOOP');
$s->check(qr/^-ERR/, 'pop3 second noop');
$s->send('NOOP');
$s->check(qr/^$/, 'pop3 max commands');

$s = Test::Nginx::POP3->new();
$s->read();

$s->send('NOOP' . CRLF . 'NOOP' . CRLF . 'NOOP');
$s->check(qr/^\+OK/, 'pop3 pipelined first noop');
$s->check(qr/^-ERR/, 'pop3 pipelined second noop rejected');
$s->check(qr/^$/, 'pop3 pipelined max commands');

# smtp

$s = Test::Nginx::SMTP->new();
$s->read();

$s->send('RSET');
$s->check(qr/^2.. /, 'smtp first rset');
$s->send('RSET');
$s->check(qr/^5.. /, 'smtp second rset rejected');
$s->send('RSET');
$s->check(qr/^$/, 'smtp max commands');

$s = Test::Nginx::SMTP->new();
$s->read();

$s->send('RSET' . CRLF . 'RSET' . CRLF . 'RSET');
$s->check(qr/^2.. /, 'smtp pipelined first rset');
$s->check(qr/^5.. /, 'smtp pipelined second rset rejected');
$s->check(qr/^$/, 'smtp pipelined max commands');

###############################################################################
