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

eval { require Net::DNS::Nameserver; };
plan(skip_all => "Net::DNS::Nameserver not installed") if $@;

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

$t->run_daemon(\&dns_daemon, 8081);
$t->run_daemon(\&dns_daemon, 8082);

eval {
	open OLDERR, ">&", \*STDERR; close STDERR;
	$t->run();
	open STDERR, ">&", \*OLDERR;
};
plan(skip_all => 'no inet6 support') if $@;

$t->waitforsocket('127.0.0.1:8081');
$t->waitforsocket('127.0.0.1:8082');

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
	my ($name, $class, $type, $peerhost, $query, $conn) = @_;
	my ($rcode, @ans, $ttl, $rdata);

	$rcode = 'NOERROR';
	$ttl = 3600;

	if (($name eq 'a.example.net') || ($name eq 'alias.example.net')) {
		($rdata) = ('127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'many.example.net')) {
		if ($conn->{sockport} == 8082) {
			return 'SERVFAIL';
		}
		($rdata) = ('127.0.0.201');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");
		($rdata) = ('127.0.0.202');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'aaaa.example.net')) {
		($type, $rdata) = ('AAAA', '::1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'short.example.net')) {
		# zero length RDATA in DNS response
		($name, $rdata) = ($name, '');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'alias.example.com')) {
		my $dname = 'example.com';
		($type, $rdata) = ('DNAME', 'example.net');
		push @ans, Net::DNS::RR->new("$dname $ttl $class $type $rdata");
		($type, $rdata) = ('CNAME', 'alias.example.net');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'cname.example.net') {
		if ($conn->{sockport} == 8082) {
			return 'SERVFAIL';
		}
		($type, $rdata) = ('CNAME', 'alias.example.net');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'cname_a.example.net') {
		($type, $rdata) = ('CNAME', 'alias.example.net');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

		($name, $type, $rdata) = ('alias.example.net', 'A', '127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'cname2.example.net') {
		# points to non-existing A
		($type, $rdata) = ('CNAME', 'nx.example.net');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'long.example.net') {
		($type, $rdata) = ('CNAME', 'a' x 63);
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'a' x 63)) {
		($rdata) = ('127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'long2.example.net') {
		($type, $rdata) = ('CNAME', 'a' x 63 . '.' . 'a' x 63 . '.'
			. 'a' x 63 . '.' . 'a' x 63);
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif (($name eq 'a' x 63 . '.' . 'a' x 63 . '.' . 'a' x 63 . '.'
			. 'a' x 63))
	{
		($rdata) = ('127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'ttl.example.net') {
		if ($conn->{sockport} == 8082) {
			return 'SERVFAIL';
		}
		($ttl, $rdata) = (1, '127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq 'ttl0.example.net') {
		if ($conn->{sockport} == 8082) {
			return 'SERVFAIL';
		}
		($ttl, $rdata) = (0, '127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq '2.example.net') {
		if ($conn->{sockport} == 8081) {
			return 'SERVFAIL';
		}
		($rdata) = ('127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} else {
		$rcode = 'NXDOMAIN';
	}

	return ($rcode, \@ans);
}

sub dns_daemon {
	my ($port) = @_;

	my $ns = Net::DNS::Nameserver->new(
		LocalAddr    => '127.0.0.1',
		LocalPort    => $port,
		Proto        => 'udp',
		ReplyHandler => \&reply_handler,
	)
		or die "Can't create nameserver object: $!\n";

	$ns->main_loop;
}

###############################################################################
