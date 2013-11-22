#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http resolver.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ipv6/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        listen       [::1]:8080;
        server_name  localhost;

        location / {
            resolver    127.0.0.1:8081;
            # to lower resolving delay for unsupported AAAA
            resolver_timeout 1s;
            proxy_pass  http://$host:8080/backend;
        }
        location /cached {
            resolver    127.0.0.1:8081 127.0.0.1:8082;
            proxy_pass  http://$host:8080/backend;
        }
        location /two {
            resolver    127.0.0.1:8081 127.0.0.1:8082;
            resolver_timeout 2s;
            proxy_pass  http://$host:8080/backend;
        }
        location /valid {
            resolver    127.0.0.1:8081 127.0.0.1:8082 valid=3s;
            resolver_timeout 2s;
            proxy_pass  http://$host:8080/backend;
        }
        location /invalid {
            proxy_pass  http://$host:8080/backend;
        }
        location /many {
            resolver    127.0.0.1:8081 127.0.0.1:8082;
            resolver_timeout 2s;
            proxy_pass  http://$host:8080/backend;
            proxy_next_upstream http_504 timeout error;
            proxy_intercept_errors on;
            proxy_connect_timeout 2s;
            error_page 504 502 /50x;
        }

        location /backend {
            return 200;
        }
        location /50x {
            return 200 $upstream_addr;
        }
    }
}

EOF

eval {
	open OLDERR, ">&", \*STDERR; close STDERR;
	$t->run();
	open STDERR, ">&", \*OLDERR;
};
plan(skip_all => 'no inet6 support') if $@;

$t->run_daemon(\&dns_daemon, 8081, $t);
$t->run_daemon(\&dns_daemon, 8082, $t);

$t->waitforfile($t->testdir . '/8081');
$t->waitforfile($t->testdir . '/8082');

$t->plan(28);

###############################################################################

like(http_host_header('a.example.net', '/'), qr/200 OK/, 'A');
like(http_host_header('short.example.net', '/'), qr/502 Bad/,
	'A short dns response');

TODO: {
local $TODO = 'support for AAAA';

like(http_host_header('aaaa.example.net', '/'), qr/200 OK/, 'AAAA');

}

like(http_host_header('nx.example.net', '/'), qr/502 Bad/, 'NXDOMAIN');
like(http_host_header('cname.example.net', '/cached'), qr/200 OK/, 'CNAME');
like(http_host_header('cname.example.net', '/cached'), qr/200 OK/,
	'CNAME cached');

# CNAME + A combined answer
# demonstrates the name in answer section different from what is asked

like(http_host_header('cname_a.example.net', '/'), qr/200 OK/, 'CNAME + A');

# CNAME refers to non-existing A

like(http_host_header('cname2.example.net', '/'), qr/502 Bad/, 'CNAME bad');
like(http_host_header('long.example.net', '/'), qr/200 OK/, 'long label');
like(http_host_header('long2.example.net', '/'), qr/200 OK/, 'long name');

# take into account DNAME

like(http_host_header('alias.example.com', '/'), qr/200 OK/, 'DNAME');

# many A records in round robin
# nonexisting IPs enumerated with proxy_next_upstream

like(http_host_header('many.example.net', '/many'),
	qr/^127.0.0.20(1:8080, 127.0.0.202:8080|2:8080, 127.0.0.201:8080)$/m,
	'A many');

like(http_host_header('many.example.net', '/many'),
	qr/^127.0.0.20(1:8080, 127.0.0.202:8080|2:8080, 127.0.0.201:8080)$/m,
	'A many cached');

# several resolver addresses with 1st ns bad
# query bad ns, negative responses are not cached

like(http_host_header('2.example.net', '/two'), qr/502 Bad/, 'two ns bad');

# query alive ns

like(http_host_header('2.example.net', '/two'), qr/200 OK/, 'two ns good');

# cached response prevents querying the next (bad) ns again

like(http_host_header('2.example.net', '/two'), qr/200 OK/, 'two ns cached');

# ttl tested with 1st ns good and 2nd ns bad
# query good ns and cache response

like(http_host_header('ttl.example.net', '/two'), qr/200 OK/, 'ttl');

# cached response prevents querying the next (bad) ns

like(http_host_header('ttl.example.net', '/two'), qr/200 OK/, 'ttl cached 1');
like(http_host_header('ttl.example.net', '/two'), qr/200 OK/, 'ttl cached 2');

sleep 2;

# expired ttl causes nginx to query the next (bad) ns

like(http_host_header('ttl.example.net', '/two'), qr/502 Bad/, 'ttl expired');

# zero ttl prohibits response caching

like(http_host_header('ttl0.example.net', '/two'), qr/200 OK/, 'zero ttl');

TODO: {
local $TODO = 'support for zero ttl';

like(http_host_header('ttl0.example.net', '/two'), qr/502 Bad/,
	'zero ttl not cached');

}

# "valid" parameter tested with 1st alive ns and 2nd bad ns
# query alive ns, and cache response

like(http_host_header('ttl.example.net', '/valid'), qr/200 OK/, 'valid');

# cached response prevents querying the next (bad) ns

like(http_host_header('ttl.example.net', '/valid'), qr/200 OK/,
	'valid cached 1');
like(http_host_header('ttl.example.net', '/valid'), qr/200 OK/,
	'valid cached 2');

sleep 2;

# expired ttl is overridden with "valid" parameter
# response is taken from cache

like(http_host_header('ttl.example.net', '/valid'), qr/200 OK/,
	'valid overrides ttl');

sleep 2;

# expired "valid" value causes nginx to query the next (bad) ns

like(http_host_header('ttl.example.net', '/valid'), qr/502 Bad/,
	'valid expired');

like(http_host_header('example.net', '/invalid'), qr/502 Bad/, 'no resolver');

###############################################################################

sub http_host_header {
	my ($host, $uri) = @_;
	return http(<<EOF);
GET $uri HTTP/1.0
Host: $host

EOF
}

###############################################################################

sub reply_handler {
	my ($recv_data, $port) = @_;

	my (@name, @rdata);

	use constant NOERROR	=> 0;
	use constant SERVFAIL	=> 2;
	use constant NXDOMAIN	=> 3;

	use constant A		=> 1;
	use constant CNAME	=> 5;
	use constant AAAA	=> 28;
	use constant DNAME	=> 39;

	use constant IN 	=> 1;

	# default values

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

	# decode name

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

	my $name = join('.', @name);
	if (($name eq 'a.example.net') || ($name eq 'alias.example.net')) {
		push @rdata, rd_addr($ttl, '127.0.0.1');

	} elsif (($name eq 'many.example.net')) {
		if ($port == 8082) {
			$rcode = SERVFAIL;
		}

		push @rdata, rd_addr($ttl, '127.0.0.201');
		push @rdata, rd_addr($ttl, '127.0.0.202');

	} elsif (($name eq 'aaaa.example.net')) {
		# AAAA [::1]

		push @rdata, pack('n3N nx15C', 0xc00c, AAAA, IN, $ttl,
			16, 1);

	} elsif (($name eq 'short.example.net')) {
		# zero length RDATA in DNS response

		push @rdata, rd_addr($ttl, '');

	} elsif (($name eq 'alias.example.com')) {
		# example.com.       3600 IN DNAME example.net.

		my @dname = ('example', 'net');
		my $rdlen = length(join '', @dname) + @dname + 1;
		push @rdata, pack("n3N n(w/a*)* x", 0xc012, DNAME, IN, $ttl,
			$rdlen, @dname);

		# alias.example.com. 3600 IN CNAME alias.example.net.

		push @rdata, pack("n3N nCa5n", 0xc00c, CNAME, IN, $ttl,
			8, 5, 'alias', 0xc02f);

	} elsif ($name eq 'cname.example.net') {
		if ($port == 8082) {
			$rcode = SERVFAIL;
		}
		push @rdata, pack("n3N nCa5n", 0xc00c, CNAME, IN, $ttl,
			8, 5, 'alias', 0xc012);

	} elsif ($name eq 'cname_a.example.net') {
		push @rdata, pack("n3N nCa5n", 0xc00c, CNAME, IN, $ttl,
			8, 5, 'alias', 0xc014);

		# points to "alias" set in previous rdata

		push @rdata, pack('n3N nC4', 0xc031, A, IN, $ttl,
			4, split(/\./, '127.0.0.1'));

	} elsif ($name eq 'cname2.example.net') {
		# points to non-existing A

		push @rdata, pack("n3N nCa2n", 0xc00c, CNAME, IN, $ttl,
			5, 2, 'nx', 0xc02f);

	} elsif ($name eq 'long.example.net') {
		push @rdata, pack("n3N nCA63x", 0xc00c, CNAME, IN, $ttl,
			65, 63, 'a' x 63);

	} elsif (($name eq 'a' x 63)) {
		push @rdata, rd_addr($ttl, '127.0.0.1');

	} elsif ($name eq 'long2.example.net') {
		push @rdata, pack("n3N n(CA63)4x", 0xc00c, CNAME, IN, $ttl, 257,
			63, 'a' x 63, 63, 'a' x 63, 63, 'a' x 63, 63, 'a' x 63);

	} elsif (($name eq 'a' x 63 . '.' . 'a' x 63 . '.' . 'a' x 63 . '.'
			. 'a' x 63))
	{
		push @rdata, rd_addr($ttl, '127.0.0.1');

	} elsif ($name eq 'ttl.example.net') {
		if ($port == 8082) {
			$rcode = SERVFAIL;
		}

		push @rdata, rd_addr(1, '127.0.0.1');

	} elsif ($name eq 'ttl0.example.net') {
		if ($port == 8082) {
			$rcode = SERVFAIL;
		}

		push @rdata, rd_addr(0, '127.0.0.1');

	} elsif ($name eq '2.example.net') {
		if ($port == 8081) {
			$rcode = SERVFAIL;
		}

		push @rdata, rd_addr(0, '127.0.0.1');

	} else {
		$rcode = NXDOMAIN;
	}

	$len = @name;
	pack("n6 (w/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
	my ($port, $t) = @_;

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr    => '127.0.0.1',
		LocalPort    => $port,
		Proto        => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (1) {
		$socket->recv($recv_data, 65536);
		$data = reply_handler($recv_data, $port);
		$socket->send($data);
	}
}

###############################################################################
