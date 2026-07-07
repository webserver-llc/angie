#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log with JSON in mail

# based on mail_error_log_filter_tags_user.t; only logging details differ

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply re/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;
use Test::Utils qw/trim :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap http rewrite/);

$t->plan(8)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    proxy_timeout  15s;
    # dead
    auth_http  http://127.0.0.1:8142/mail/auth;

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

    error_log %%TESTDIR%%/filtered_usertag1.json format=json
              filter=tag:srv1;

    error_log %%TESTDIR%%/filtered_usertag2.json format=json
              filter=tag:srv2;
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

my $d = $t->testdir();

my $with_debug = $t->has_module('debug');

$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);

$t->waitforsocket('127.0.0.1:' . port(8144));

$t->run();

###############################################################################

my $s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8143));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered error on srv1');

$s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8145));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered error on srv2');

$s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8146));
$s->ok('greeting');
$s->send('a03 LOGIN test@example.com secret');
$s->check(qr/BAD/, 'triggered error on srv3');

$t->stop();

my @raw_lines1 = get_lines("$d/filtered_usertag1.json");
my @raw_lines2 = get_lines("$d/filtered_usertag2.json");

verify_mail_json_lines(\@raw_lines1, 'srv1');
verify_mail_json_lines(\@raw_lines2, 'srv2');

###############################################################################

sub verify_mail_json_lines {
	my ($lines, $srv) = @_;

	while (my ($k, $line) = each @{ $lines }) {
		verify_json_log_entry($line, $srv,
			'mail json entry at line ' . ($k + 1));
	}
}

sub verify_json_log_entry {
	my ($line, $srv, $msg) = @_;

	my $j = JSON->new();
	my $json = $j->decode($line);

	my $expected = {
		time       => $LOG_TIME_RE,
		pid        => $NUM_RE,
		tid        => $NUM_RE,
		level      => re(qr/info|error|warn|debug/),
		connection => $NUM_RE,
		message    => re(qr/.*/),
	};
	$expected->{src} = re(qr/.*/)
		if $with_debug;

	# some messages may contain errors
	if ($json->{error}) {
		$expected->{error} = {
			message => re(qr/.*/),
			code    => $NUM_RE,
		},
	}

	my @tags = ('mail', $srv);

	if ($json->{mail}) {
		$expected->{mail} = {
			action => re(qr/.*/),
			client => re(qr/127\.0\.0\.1:\d+/),
			server => re(qr/127\.0\.0\.1:\d+/),
			login  => 'test@example.com',
		};
		$expected->{tags} = \@tags;
	}

	cmp_deeply($json, $expected, $msg)
		or diag $line;
}

###############################################################################

sub get_lines {
	my ($file) = @_;

	open my $fh, '<', $file or return "$!";

	my @lines;
	for my $line (<$fh>) {
		$line = trim($line);
		push @lines, $line;
	}

	return @lines;
}

###############################################################################
