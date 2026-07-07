#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for error_log with user-defined tags in stream

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


my $t = Test::Nginx->new()->has(qw/stream/)
	->plan(8)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}


stream {
    %%TEST_GLOBALS_STREAM%%

    log_format proxy '$remote_addr $status $status $connection $server_port';
    access_log stream_access.log proxy;

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8081;
        listen       127.0.0.1:8082;

        # dead upstream
        proxy_pass 127.0.0.1:8083;
        proxy_connect_timeout 1ms;

        error_log_user_tag "$connection";
        error_log_user_tag "$server_port";

        error_log %%TESTDIR%%/filtered_usertag1.log
                  filter=tag:3
                  filter=tag:%%PORT_8081%%;

        error_log %%TESTDIR%%/filtered_usertag2.log
                  filter=tag:5
                  filter=tag:%%PORT_8082%%;

        error_log %%TESTDIR%%/filtered_usertag-all.log;

		# XXXX
        error_log %%TESTDIR%%/all.json format=json;
    }
}

EOF


$t->run();

is(get(port(8080)), undef, 'query with non-matching user tags');
is(get(port(8081)), undef, 'query with tag1');
is(get(port(8082)), undef, 'query with tag2');

$t->stop();

is($t->find_in_file('filtered_usertag-all.log', 'connecting to upstream'), 3,
	'logged into filtered_usertag-all.log');

is($t->find_in_file('filtered_usertag1.log', 'connecting to upstream'), 1,
	'single message in filtered_usertag1.log');
is($t->find_in_file('filtered_usertag1.log', qr/bytes_to_upstream/), 1,
	'filtered tag1 correct message');

is($t->find_in_file('filtered_usertag2.log', 'connecting to upstream'), 1,
	'single message in filtered_usertag2.log');
is($t->find_in_file('filtered_usertag2.log', qr/bytes_to_upstream/), 1,
	'filtered tag2 correct message');


###############################################################################

sub get {
	my $port = shift;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => "127.0.0.1:$port"
	)
		or die "Can't connect to nginx: $!\n";

	my $r = http_get('/nonexist', socket => $s);
	if (!$r) {
		$r = undef;
	}

	return $r;
}

###############################################################################
