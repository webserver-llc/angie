#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream proxy module, limit rate directives.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    # download and upload rates are set equal to the maximum
    # number of bytes transmitted

    # proxy_download_rate value comes from following calculations:
    # test string length (1000) + whitespace (1) + time string length (10)

    proxy_download_rate      1011;
    proxy_upload_rate        1000;

    server {
        listen               127.0.0.1:8081;
        proxy_pass           127.0.0.1:8080;
    }

    server {
        listen               127.0.0.1:8082;
        proxy_pass           127.0.0.1:8080;
        proxy_download_rate  0;
        proxy_upload_rate    0;
    }

    server {
        listen               127.0.0.1:8083;
        proxy_pass           127.0.0.1:8080;
        proxy_download_rate  1;
    }

    server {
        listen               127.0.0.1:8084;
        proxy_pass           127.0.0.1:8080;
        proxy_upload_rate    1;
    }

    server {
        listen               127.0.0.1:8085;
        proxy_pass           127.0.0.1:8080;
        proxy_download_rate  250;
    }

    server {
        listen               127.0.0.1:8086;
        proxy_pass           127.0.0.1:8090;
        proxy_upload_rate    250;
    }
}

EOF

$t->run_daemon(\&stream_daemon, 8080);
$t->run_daemon(\&stream_daemon, 8090);

$t->try_run('no proxy_download_rate and/or proxy_upload_rate')->plan(8);

$t->waitforsocket('127.0.0.1:8080');
$t->waitforsocket('127.0.0.1:8090');

###############################################################################

my $str = '1234567890' x 100;

my %r = stream_get($str, peer => '127.0.0.1:8081');
is($r{'data'}, $str, 'exact limit');

%r = stream_get($str, peer => '127.0.0.1:8082');
is($r{'data'}, $str, 'unlimited');

SKIP: {
skip 'unsafe on VM', 2 unless $ENV{TEST_NGINX_UNSAFE};

# if interaction between backend and client is slow then proxy can add extra
# bytes to upload/download data

%r = stream_get($str, peer => '127.0.0.1:8083', readonce => 1);
is($r{'data'}, '1', 'download - one byte');

%r = stream_get($str, peer =>  '127.0.0.1:8084');
is($r{'data'}, '1', 'upload - one byte');

}

# Five chunks are split with four 1s delays + 2s error:
# the first two chunks are halfs of test string 
# and the third one is some extra data from backend.

%r = stream_get($str, peer =>  '127.0.0.1:8085');
my $diff = time() - $r{'time'};
cmp_ok(abs($diff - 4), '<=', 2, 'download - time');
is($r{'data'}, $str, 'download - data');

my $time = time();
%r = stream_get($str . 'close', peer => '127.0.0.1:8086');
$diff = time() - $time;
cmp_ok(abs($diff - 4), '<=', 2, 'upload - time');
is($r{'data'}, $str . 'close', 'upload - data');

###############################################################################

sub stream_get {
	my ($data, %extra) = @_;

	my $s = stream_connect($extra{'peer'});
	stream_write($s, $data);

	$data = '';
	while (my $buf = stream_read($s)) {
		$data .= $buf;
		last if $extra{'readonce'};
	}
	$data =~ /([\S]*)\s?(\d+)?/;

	return ('data' => $1, 'time' => $2);
}

sub stream_connect {
	my $peer = shift;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => $peer
	)
		or die "Can't connect to nginx: $!\n";

	return $s;
}

sub stream_write {
	my ($s, $message) = @_;

	local $SIG{PIPE} = 'IGNORE';

	$s->blocking(0);
	while (IO::Select->new($s)->can_write(1.5)) {
		my $n = $s->syswrite($message);
		last unless $n;
		$message = substr($message, $n);
		last unless length $message;
	}

	if (length $message) {
		$s->close();
	}
}

sub stream_read {
	my ($s) = @_;
	my ($buf);

	$s->blocking(0);
	if (IO::Select->new($s)->can_read(3)) {
		$s->sysread($buf, 1024);
	};

	log_in($buf);
	return $buf;
}

###############################################################################

sub stream_daemon {
	my $port = shift;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($server);

	local $SIG{PIPE} = 'IGNORE';

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($server == $fh) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif (stream_handle_client($fh)) {
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub stream_handle_client {
	my ($client) = @_;

	log2c("(new connection $client)");

	$client->sysread(my $buffer, 65536) or return 1;

	log2i("$client $buffer");

	$buffer .= " " . time() if $client->sockport() eq 8080;

	log2o("$client $buffer");

	$client->syswrite($buffer);

	return $client->sockport() eq 8080 ? 1 : $buffer =~ /close/;
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

###############################################################################
