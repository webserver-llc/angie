#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for stream upstream max_conns statistics.

###############################################################################

use warnings;
use strict;

use Test::Deep qw/ cmp_deeply superhashof noneof /;
use Test::More;
use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;
use Test::Utils qw/ get_json /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_upstream_zone http http_api/)
	->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    upstream u1 {
        zone z1 1m;
        server 127.0.0.1:8081 max_conns=1;
        server 127.0.0.1:8082;
    }

    server {
        listen      127.0.0.1:8091;
        proxy_pass  u1;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /api/ {
            api /;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, port(8081), port(8082), port(8085));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8085));

###############################################################################

my ($p1, $p2) = (port(8081), port(8082));

# send 4 requests
my $count = 4;
my $upstream = 'u1';

my @sockets = http_get_multi('8091', '/' . $upstream, $count);
for (1 .. 20) {
	last if IO::Select->new(@sockets)->can_read(3) == $count;
	select undef, undef, undef, 0.01;
}

my $api = get_json("/api/status/stream/upstreams/$upstream/peers");
note(explain({api => $api}));

my $expected_api = superhashof({
	"127.0.0.1:$p1" => superhashof({
		selected  => superhashof({current => 1, total => 1}),
		state     => 'busy',
		max_conns => 1,
	}),
	"127.0.0.1:$p2" => superhashof({
		selected => superhashof({current => 3, total => 3}),
		state => 'up',
	}),
});
cmp_deeply($api, $expected_api, 'api (1)');
cmp_deeply([keys %{ $api->{"127.0.0.1:$p2"} }], noneof('max_conns'),
	"no max_conns in $p2");

get(8085, '/closeall');

my $stat = http_end_multi(\@sockets);

cmp_deeply($stat, {$p1 => 1, $p2 => 3}, 'distribution of requests');

$api = get_json("/api/status/stream/upstreams/$upstream/peers");
note(explain({api => $api}));

$expected_api = superhashof({
	"127.0.0.1:$p1" => superhashof({
		selected  => superhashof({current => 0, total => 1}),
		state     => 'up',
		max_conns => 1,
	}),
	"127.0.0.1:$p2" => superhashof({
		selected => superhashof({current => 0, total => 3}),
		state    => 'up',
	}),
});
cmp_deeply($api, $expected_api, 'api (2)');

###############################################################################

sub get {
	my ($port, $uri, %opts) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1',
		PeerPort => port($port),
	)
		or die "Can't connect to nginx: $!\n";

	http_get($uri, socket => $s, %opts);
}

sub http_get_multi {
	my ($port, $uri, $count, $wait) = @_;

	my @sockets;
	for (0 .. $count - 1) {
		$sockets[$_] = get($port, $uri, start => 1);
		IO::Select->new($sockets[$_])->can_read($wait) if $wait;
	}

	return @sockets;
}

sub http_end_multi {
	my ($sockets) = @_;

	my %ports;
	for my $sock (@$sockets) {
		my $r = http_end($sock);
		if ($r && $r =~ /X-Port: (\d+)/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
		close $sock;
	}

	return \%ports;
}

###############################################################################

sub http_daemon {
	my (@ports) = @_;

	my (@socks, @clients);
	for my $port (@ports) {
		my $server = IO::Socket::INET->new(
			Proto => 'tcp',
			LocalHost => "127.0.0.1:$port",
			Listen => 42,
			Reuse => 1
		)
			or die "Can't create listening socket: $!\n";
		push @socks, $server;
	}

	my $sel = IO::Select->new(@socks);
	my $skip = 4;
	my $count = 0;

	local $SIG{PIPE} = 'IGNORE';

OUTER:
	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if (grep $_ == $fh, @socks) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);
				$count++;

			} else {
				my @busy = grep { $_->sockport() } @ready;

				# finish other handles
				if ($fh->sockport() == port(8085) && @busy > 1
					&& grep $_->sockport() != port(8085),
					@busy)
				{
					next;
				}

				# late events in other handles
				if ($fh->sockport() == port(8085) && @busy == 1
					&& $count > 1 && $skip-- > 0)
				{
					select undef, undef, undef, 0.1;
					next OUTER;
				}

				my $rv = process_socket($fh, \@clients);
				if ($rv == 1) {
					$sel->remove($fh);
					$fh->close;
				}
				if ($rv == 2) {
					for (@clients) {
						$sel->remove($_);
						$_->close;
					}
					$sel->remove($fh);
					$fh->close;
					$skip = 4;
				}
				$count--;
			}
		}
	}
}

# Returns true to close connection
sub process_socket {
	my ($client, $saved) = @_;

	my $headers = '';
	while (<$client>) {
		$headers .= $_;
		last if (/^\x0d?\x0a?$/);
	}
	return 1 if $headers eq '';

	my $uri = '';
	$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;
	return 1 if $uri eq '';

	my $port = $client->sockport();
	Test::Nginx::log_core('||', "$port: response, 200");
	print $client <<EOF;
HTTP/1.1 200 OK
X-Port: $port

OK
EOF

	return 2 if $uri =~ /closeall/;
	return 1 if $uri =~ /close/;

	push @$saved, $client;
	return 0;
}

###############################################################################
