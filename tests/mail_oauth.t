#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for mail module, XOAUTH2 and OAUTHBEARER authentication.

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;
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

my $t = Test::Nginx->new()->has(qw/mail imap pop3 smtp http map rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    proxy_pass_error_message  on;
    proxy_timeout  15s;
    timeout  2s;
    auth_http  http://127.0.0.1:8080/mail/auth;

    server {
        listen     127.0.0.1:8143;
        protocol   imap;
        imap_auth  plain oauthbearer xoauth2;
    }
    server {
        listen     127.0.0.1:8110;
        protocol   pop3;
        pop3_auth  plain oauthbearer xoauth2;
    }
    server {
        listen     127.0.0.1:8025;
        protocol   smtp;
        smtp_auth  plain oauthbearer xoauth2;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $http_auth_protocol $proxy_port {
	imap %%PORT_8144%%;
	pop3 %%PORT_8111%%;
	smtp %%PORT_8026%%;
    }

    map $http_auth_user:$http_auth_pass $reply {
	test@example.com:secretok OK;
	test=,@example.com:secretok OK;
	default auth-failed;
    }

    map $http_auth_pass $passw {
	secretok secret;
    }

    map $http_auth_pass $sasl {
	saslfail "eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /mail/auth {
            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port $proxy_port;
            add_header Auth-Pass $passw;
            add_header Auth-Wait 1;
            add_header Auth-Error-SASL $sasl;
            return 204;
        }
    }
}

EOF

$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);
$t->run_daemon(\&Test::Nginx::POP3::pop3_test_daemon);
$t->run_daemon(\&Test::Nginx::SMTP::smtp_test_daemon);
$t->try_run('no oauth support')->plan(48);

$t->waitforsocket('127.0.0.1:' . port(8144));
$t->waitforsocket('127.0.0.1:' . port(8111));
$t->waitforsocket('127.0.0.1:' . port(8026));

###############################################################################

# AUTHBEARER SASL mechanism
# https://datatracker.ietf.org/doc/html/rfc7628

# XOAUTH2 SASL mechanism
# https://developers.google.com/gmail/imap/xoauth2-protocol

my $s;
my $token = encode_base64(
	"n,a=test\@example.com,\001auth=Bearer secretok\001\001", '');
my $token_escaped = encode_base64(
	"n,a=test=3D=2C\@example.com,\001auth=Bearer secretok\001\001", '');
my $token_saslfail = encode_base64(
	"n,a=test\@example.com,\001auth=Bearer saslfail\001\001", '');
my $token_bad = encode_base64(
	"n,a=test\@example.com,\001auth=Bearer bad\001\001", '');

my $token_xoauth2 = encode_base64(
	"user=test\@example.com\001auth=Bearer secretok\001\001", '');
my $token_xoauth2_saslfail = encode_base64(
	"user=test\@example.com\001auth=Bearer saslfail\001\001", '');
my $token_xoauth2_bad = encode_base64(
	"user=test\@example.com\001auth=Bearer bad\001\001", '');

# IMAP

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token);
$s->ok('imap oauthbearer success');

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_escaped);
$s->ok('imap oauthbearer escaped login');

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER');
$s->check(qr/\+ /, 'imap oauthbearer challenge');
$s->send($token);
$s->ok('imap oauthbearer success after challenge');

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_bad);
$s->check(qr/^1 NO auth-failed/, 'imap oauthbearer non-sasl error');

sleep(3);

my @ready = $s->can_read(0);
is(scalar @ready, 1, "imap ready for reading");
ok($s->eof(), "imap session closed");

# fail, sasl failure method

$s = Test::Nginx::IMAP->new();
$s->read();
my $start = time;
$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'imap oauthbearer sasl failure');
my $wait_time = time - $start;
ok($wait_time >= 1, 'imap oauthbearer error delayed');
$s->send('AQ==');
$s->check(qr/^1 NO auth-failed/,
	'imap oauthbearer auth failure after dummy response');

# fail, sasl failure method, invalid client response

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'imap oauthbearer sasl failure');
$s->send('foo');
$s->check(qr/^1 BAD /, 'imap oauthbearer invalid command after invalid line');

# fail, sasl failure method, multiple attempts, then success

$s = Test::Nginx::IMAP->new();
$s->read();

$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'imap oauthbearer sasl failure');
$s->send('AQ==');
$s->check(qr/^1 NO auth-failed/,
	'imap oauthbearer auth failure after dummy response');

$s->send('1 AUTHENTICATE OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'imap oauthbearer sasl failure next');
$s->send('foo');
$s->check(qr/^1 BAD/, 'imap oauthbearer invalid command after invalid line');

$s->send('1 AUTHENTICATE OAUTHBEARER');
$s->check(qr/\+ /, 'imap oauthbearer challenge after fail');
$s->send($token);
$s->ok('imap oauthbearer success after fail');

# IMAP XOAUTH2

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE XOAUTH2 ' . $token_xoauth2);
$s->ok('imap xoauth2 success');

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE XOAUTH2');
$s->check(qr/^\+ /, 'imap xoauth2 challenge');
$s->send($token_xoauth2);
$s->ok('imap xoauth2 success after challenge');

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE XOAUTH2 ' . $token_xoauth2_saslfail);
$s->check(qr/^\+ eyJz/, 'imap xoauth2 with bad token');
$s->send('');
$s->check(qr/^1 NO auth-failed/, 'imap xoauth2 auth failure after empty line');

$s->send('1 AUTHENTICATE XOAUTH2 ' . $token_xoauth2_saslfail);
$s->check(qr/^\+ eyJz/, 'imap xoauth2 with bad token next');
$s->send('foo');
$s->check(qr/^1 BAD/, 'imap xoauth2 invalid command after invalid line');

$s->send('1 AUTHENTICATE XOAUTH2 ' . $token_xoauth2);
$s->ok('imap xoauth2 success after fail');

# POP3

$s = Test::Nginx::POP3->new();
$s->read();
$s->send('AUTH OAUTHBEARER ' . $token);
$s->ok('pop3 oauthbearer success');

$s = Test::Nginx::POP3->new();
$s->read();
$s->send('AUTH OAUTHBEARER');
$s->check(qr/^\+ /, 'pop3 oauthbearer challenge');
$s->send($token);
$s->ok('pop3 oauthbearer success after challenge');

$s = Test::Nginx::POP3->new();
$s->read();
$s->send('AUTH OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'pop3 oauthbearer sasl failure');
$s->send('AQ==');
$s->check(qr/^-ERR /, 'pop3 oauthbearer auth failure after dummy response');

$s->send('AUTH OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^\+ eyJz/, 'pop3 oauthbearer sasl failure next');
$s->send('');
$s->check(qr/^-ERR /, 'pop3 oauthbearer invalid command after invalid line');

$s->send('AUTH OAUTHBEARER ' . $token);
$s->ok('pop3 oauthbearer success after fail');

# POP3 XOAUTH2

$s = Test::Nginx::POP3->new();
$s->read();
$s->send('AUTH XOAUTH2 ' . $token_xoauth2);
$s->ok('pop3 xoauth2 success');

$s = Test::Nginx::POP3->new();
$s->read();
$s->send('AUTH XOAUTH2');
$s->check(qr/^\+ /, 'pop3 xoauth2 challenge');
$s->send($token_xoauth2);
$s->ok('pop3 xoauth2 success after challenge');

# SMTP

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . $token);
$s->authok('smtp oauthbearer success');

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER');
$s->check(qr/^334 /, 'smtp oauthbearer challenge');
$s->send($token);
$s->authok('smtp oauthbearer success after challenge');

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^334 eyJz/, 'smtp oauthbearer sasl failure');
$s->send('AQ==');
$s->check(qr/^535 /, 'smtp oauthbearer auth failure after dummy response');

$s->send('AUTH OAUTHBEARER ' . $token_saslfail);
$s->check(qr/^334 eyJz/, 'smtp oauthbearer sasl failure next');
$s->send('foo');
$s->check(qr/^500 /, 'smtp oauthbearer invalid command after invalid line');

$s->send('AUTH OAUTHBEARER ' . $token);
$s->authok('smtp oauthbearer success after fail');

# SMTP XOAUTH2

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH XOAUTH2 ' . $token_xoauth2);
$s->authok('smtp xoauth2 success');

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH XOAUTH2');
$s->check(qr/^334 /, 'smtp xoauth2 challenge');
$s->send($token_xoauth2);
$s->authok('smtp xoauth2 success after challenge');

###############################################################################
