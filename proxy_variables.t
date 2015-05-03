#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http proxy module with upstream variables.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(8)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8081;
        server 127.0.0.1:8081;
    }

    log_format time $upstream_header_time:$upstream_response_time;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            add_header X-Header-Time $upstream_header_time;
            proxy_pass http://127.0.0.1:8081;
            access_log %%TESTDIR%%/time.log time;
        }

        location /pnu {
            add_header X-Header-Time $upstream_header_time;
            add_header X-Response-Time $upstream_response_time;
            proxy_pass http://u/bad;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, 8081);
$t->run()->waitforsocket('127.0.0.1:8081');

###############################################################################

my $re = qr/(\d\.\d{3})/;
my ($ht, $rt, $ht2, $rt2);

($ht) = http_get('/header') =~ /X-Header-Time: $re/;
cmp_ok($ht, '>=', 1, 'header time - slow response header');

($ht) = http_get('/body') =~ /X-Header-Time: $re/;
cmp_ok($ht, '<', 1, 'header time - slow response body');

my $r = http_get('/pnu');
($ht) = $r =~ /X-Header-Time: ($re)/;
($rt) = $r =~ /X-Response-Time: ($re)/;

is($ht, $rt, 'header time - bad response');
like($r, qr/X-Header-Time: $re, $re/, 'header time - next');

$t->stop();

($ht, $rt, $ht2, $rt2) = $t->read_file('time.log') =~ /^$re:$re\n$re:$re$/;

cmp_ok($ht, '>=', 1, 'header time log - slow response header');
cmp_ok($ht2, '<', 1, 'header time log - slow response body');

cmp_ok($rt, '>=', 1, 'response time log - slow response header');
cmp_ok($rt2, '>=', 1, 'response time log - slow response body');

###############################################################################

sub http_daemon {
	my ($port) = @_;
	my $once = 1;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;
		next unless defined $uri;

		if ($uri =~ 'bad' && $once) {
			$once = 0;
			sleep 1;
			next;
		}

		if ($uri =~ 'header') {
			sleep 1;
		}

		print $client <<EOF;
HTTP/1.1 200 OK
Connection: close

SEE-THIS-
EOF

		if ($uri =~ 'body') {
			sleep 1;
		}

		print $client 'AND-THIS';
	}
}

###############################################################################
