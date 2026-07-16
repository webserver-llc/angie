#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for JSON escaping in error_log

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Deep qw/cmp_deeply re/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/trim :re/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant ERROR_LOG_BUFFER_SIZE => 2048;

my $t = Test::Nginx->new()->has(qw/stream http/)
	->plan(6)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    error_log %%TESTDIR%%/stream_error_log_info.json format=json info;
    error_log %%TESTDIR%%/stream_error_log_info.log info;

    upstream u {
        server 127.0.0.1:8083; # dead
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        proxy_pass   u;
    }
    server {
        listen       127.0.0.1:8082;
        return       STREAM;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;
        location / {
            return 200 HTTP;
        }
    }
}

EOF


$t->run();

like(http_get('/'), qr/HTTP/, 'prepare');

$t->stop();

###############################################################################

my $with_debug = $t->has_module('debug');

my @raw_lines = get_lines($t->testdir() . '/stream_error_log_info.json');

verify_stream_json_lines(\@raw_lines);

###############################################################################

sub verify_stream_json_lines {
	my ($lines) = @_;

	while (my ($k, $line) = each @{ $lines }) {
		verify_json_log_entry($line, 'stream json entry at line ' . ($k + 1));
	}
}

sub verify_json_log_entry {
	my ($line, $msg) = @_;

	my $j = JSON->new();
	my $json = $j->decode($line);

	my $expected = {
		time       => $TIME_RE,
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

	my @stream_tags = (qw/stream/);
	my @session_tags = (qw/stream upstream peer/);

	my $tags = \@stream_tags;

	my $expected_session = {
		upstream            => re(qr/127\.0\.0\.1:\d+/),
		bytes_from_client   => $NUM_RE,
		bytes_to_client     => $NUM_RE,
		bytes_from_upstream => $NUM_RE,
		bytes_to_upstream   => $NUM_RE,
	};

	my $expected_stream  = {
		action   => re(qr/.*/),
		client   => re(qr/127\.0\.0\.1:\d+/),
		server   => '127.0.0.1:'.port(8080),
		protocol => 'tcp',
	};

	if ($json->{stream}) {
		my $action = $json->{stream}{action} // '';

		if ($action ne 'initializing session') {
			$expected_stream->{session} = $expected_session;
			$tags = \@session_tags;
		}

		$expected->{stream} = $expected_stream;
		$expected->{tags}   = $tags;
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
