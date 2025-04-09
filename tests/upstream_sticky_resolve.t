#!/usr/bin/perl

# (C) 2022 Web Server LLC

# Tests for upstream module with sticky feature.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;
use Test::Utils qw/ get_json annotate /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => '127.0.0.3 local address required')
	unless defined IO::Socket::INET->new( LocalAddr => '127.0.0.3' );

my $t = Test::Nginx->new()
	->has(qw/http http_api proxy rewrite upstream_sticky upstream_zone/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # direct access to all backends for test harness

    upstream backend_1 {
        server 127.0.0.1:%%PORT_8081%%;
        sticky cookie sticky;
    }

    upstream backend_2 {
        server 127.0.0.2:%%PORT_8082%%;
        sticky cookie sticky;
    }

    upstream backend_3 {
        server 127.0.0.3:%%PORT_8083%%;
        sticky cookie sticky;
    }

    upstream backend_4 {
        server 127.0.0.4:%%PORT_8084%% sid=aaaa;
        sticky cookie sticky;
    }

    upstream backend_5 {
        server 127.0.0.5:%%PORT_8085%% sid=bbbbb;
        sticky cookie sticky;
    }

    # Upstreams for test cases: 1 upstream per testcase

    upstream tc_1 {
        zone z 1m;

        server b1.example.com:%%PORT_8081%% resolve;
        server b2.example.com:%%PORT_8082%% resolve;
        server b3.example.com:%%PORT_8083%% resolve;
        server b4.example.com:%%PORT_8084%% resolve sid=aaaa;
        server b5.example.com:%%PORT_8085%% resolve sid=bbbbb;

        resolver 127.0.0.1:5252 valid=1s ipv6=off;

        sticky cookie sticky;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;

        # Entry points for test harness

        location /backend_1 { proxy_pass http://backend_1/; }
        location /backend_2 { proxy_pass http://backend_2/; }
        location /backend_3 { proxy_pass http://backend_3/; }
        location /backend_4 { proxy_pass http://backend_4/; }
        location /backend_5 { proxy_pass http://backend_5/; }

        location /api/ {
            api /;
        }

        # Entry points for corresponding test cases

        location /tc_1 { proxy_pass http://tc_1; }
    }

    # Backends used in tests

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        location / {
            add_header X-Backend B1;
            return 200 B1;
        }

        location /bad {
            add_header X-Backend B1;
            return 503;
        }
    }

    server {
        listen       127.0.0.2:%%PORT_8082%%;
        location / {
            add_header X-Backend B2;
            return 200 B2;
        }
        location /bad {
            add_header X-Backend B2;
            return 503;
        }
    }

    server {
        listen       127.0.0.3:%%PORT_8083%%;
        location / {
            add_header X-Backend B3;
            return 200 B3;
        }
    }

    server {
        listen       127.0.0.4:%%PORT_8084%%;
        location / {
            add_header X-Backend B4;
            return 200 B4;
        }
    }

    server {
        listen       127.0.0.5:%%PORT_8085%%;
        location / {
            add_header X-Backend B5;
            return 200 B5;
        }
    }

    server {
        listen       127.0.0.6:%%PORT_8085%%;
        location / {
            add_header X-Backend B6;
            return 200 B6;
        }
    }
}

EOF

# TODO: use substituted ports for parallel execution for DNS server
my %addrs = (
    'b1.example.com' => ['127.0.0.1', '::1'],
    'b2.example.com' => ['127.0.0.2', '::1'],
    'b3.example.com' => ['127.0.0.3', '::1'],
    'b4.example.com' => ['127.0.0.4', '::1'],
    'b5.example.com' => ['127.0.0.5', '127.0.0.6' ,'::1']
);

$t->start_resolver(5252, \%addrs);

$t->run()->plan(24);

my @ports = my ($p1, $p2, $p3, $p4, $p5) =
	(port(8081), port(8082), port(8083), port(8084), port(8085));

# wait for all backends to be available
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforsocket('127.0.0.2:' . port(8082));
$t->waitforsocket('127.0.0.3:' . port(8083));
$t->waitforsocket('127.0.0.4:' . port(8084));
$t->waitforsocket('127.0.0.5:' . port(8085));


###############################################################################

# prepare for testing: get sticky cookies for all backends

my %bmap = collect_cookies("/backend_");

###############################################################################

tc1("sticky with zone and resolve");

# remove b3..b5 from DNS to trigger removal of sticky-enabled peer

%addrs = (
    'b1.example.com' => ['127.0.0.1', '::1'],
    'b2.example.com' => ['127.0.0.2', '::1'],
);

my @nxaddrs = ('b3.example.com', 'b4.example.com', 'b5.example.com');
$t->restart_resolver(5252, \%addrs, {nxaddrs => \@nxaddrs});

# let angie resolve
select undef, undef, undef, 2;

tc2("sticky after peers removed");

###############################################################################

# regression: no cookie is set, RR works normally
# - upstream has no sticky directive, no keepalive
# - make 4 requests, expect 4 responses from corresponding backends, in order
sub tc1 {
	annotate(@_);

	for (1 .. 4) {
		my %res = get_sticky_reply("/tc_1", $bmap{"B$_"});
		my $backend = $res{backend};
		my $cookie  = $res{cookie};

		is($backend, "B$_", "backend $_ is selected by sticky");
		is($cookie, $bmap{"B$_"}, "correct cookie is set for backend $_");
	}

	my $j = get_json("/api/status/http/upstreams/tc_1/peers/127.0.0.4:$p4");
	is($j->{sid}, $bmap{B4}, "b4 has proper sid");

	$j = get_json("/api/status/http/upstreams/tc_1/peers/127.0.0.5:$p5");
	is($j->{sid}, $bmap{B5}, "b5/1 has proper sid");

	$j = get_json("/api/status/http/upstreams/tc_1/peers/127.0.0.6:$p5");
	is($j->{sid}, $bmap{B5}, "b5/2 has same sid as b5/1");

	# query b5 using id;
	# 2 peers share same ID, sticky selects 1st found
	# make 4 request with sticky ID and expect the same
	# backend to be selected 4 times
	my $initial_back;
	for (1 .. 4) {
		my %res = get_sticky_reply("/tc_1", $bmap{"B5"});
		my $backend = $res{backend};
		my $cookie  = $res{cookie};

		if (!defined($initial_back)) {
			$initial_back = $backend;
			is((($backend eq "B5") or ($backend eq "B6")), 1,
				"B5 or B6 is selected ($backend)");

		} else {
			is($initial_back, $backend, "$initial_back again selected");
		}

		# cookie is always from B5
		is($cookie, $bmap{"B5"}, "cookie is set to B5 id");
	}
}

sub tc2 {
	annotate(@_);

	# no changes are expected for b1..b2
	for (1 .. 2) {
		my %res = get_sticky_reply("/tc_1", $bmap{"B$_"});
		my $backend = $res{backend};

		is($backend, "B$_", "backend $_ is selected by sticky");
	}

	# b3..b5 are gone
	for (3 .. 5) {
		my $port = $ports[$_ - 1];
		my $j = get_json("/api/status/http/upstreams/tc_1/peers/127.0.0.$_:$port}}");
		is($j->{error}, "PathNotFound", "b$_ removed");
	}
}

###############################################################################

# makes an HTTP request to passed $uri (with optional cookie)
# returns hash with various response properties: backend, cookie, attrs, code
sub get_sticky_reply {
	my ($uri, $sticky_cookie, $cookie_name) = @_;

	$cookie_name //= "sticky";

	my $response;
	if (defined $sticky_cookie) {
		$response = http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
Cookie: $cookie_name=$sticky_cookie

EOF
	} else {
		$response = http_get($uri);
	}

	my ($backend) = $response =~ /X-Backend: (B\d+)/;
	my ($resp_cookie_name) = $response =~ /Set-Cookie: (\w+)=\w+/;
	my ($cookie) = $response =~ /Set-Cookie: \w+=(\w+)/;
	my ($attrs) = $response =~ /Set-Cookie: \w+=\w+; (.*)\r\n/;
	my ($code) = $response =~ qr!HTTP/1.1 (\d\d\d)!ms;

	my %result = (
		backend     => $backend,
		cookie      => $cookie,
		cookie_name => $resp_cookie_name,
		attrs       => $attrs,
		code        => $code,
	);

	return %result;
}

# visits all backends via /backend_NNN uri and returns
# hash with backend <-> cookie mapping
sub collect_cookies {
	my ($uri_template, $secret_arg) = @_;

	note("# Backend cookies [$uri_template]:\n");

	my %backend_cookies;
	for (1 .. 5) {

		my $url;
		if (!defined($secret_arg)) {
			$url = " $uri_template$_/good";
		} else {
			$url = " $uri_template$_/good?$secret_arg";
		}

		my %result = get_sticky_reply($url);

		my $backend = $result{backend};
		my $cookie  = $result{cookie};

		note("#	$backend <=> $cookie\n");

		$backend_cookies{$backend} = $cookie;
	}

	return %backend_cookies;
}

###############################################################################
