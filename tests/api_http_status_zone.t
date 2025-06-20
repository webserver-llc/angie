#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for http 'status_zone' directive.

###############################################################################

use warnings;
use strict;

use Socket qw/$CRLF/;
use Test::Deep qw/cmp_deeply/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_api http_ssl map socket_ssl_sni/)
	->has(qw/sni/)
	->has_daemon('openssl')->plan(2153)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen %%PORT_8080%%;

        location /status/ {
            api /status/;
        }
    }

    server {
        listen %%PORT_8081%%;

        status_zone $uri zone=uri;

        location / {
            status_zone $uri zone=uri;
            return 200;
        }
    }

    server {
        listen %%PORT_8082%%;

        status_zone $uri zone=uri;

        location / {
            status_zone $uri zone=uri:15;
            return 200;
        }
    }

    server {
        listen %%PORT_8083%%;

        status_zone $uri zone=uri:15;

        location / {
            status_zone $uri zone=uri:15;
            return 200;
        }
    }

    server {
        listen %%PORT_8084%%;
        server_name *.a.example.com;

        status_zone $host zone=a_host:5;

        location / {
            status_zone $host zone=a_host:5;
            return 200;
        }
    }

    server {
        listen %%PORT_8084%%;
        server_name *.b.example.com;

        status_zone $host zone=b_host:5;

        location / {
            status_zone $host zone=b_host:5;
            return 200;
        }
    }

    server {
        listen %%PORT_8085%%;

        status_zone single;

        location / {
            status_zone single;
            return 200;
        }
    }

    server {
        listen %%PORT_8086%%;

        status_zone single;

        location / {
            status_zone single;
            return 200;
        }
    }

    server {
        listen %%PORT_8087%% ssl;
        server_name *.sni.a.example.com;

        status_zone $ssl_server_name zone=sni:10;

        ssl_protocols TLSv1.2;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        location / {
            status_zone $ssl_server_name zone=sni:10;
            return 200;
        }
    }

    server {
        listen %%PORT_8088%% ssl;
        server_name *.sni.b.example.com;

        status_zone $ssl_server_name zone=sni;

        ssl_protocols TLSv1.2;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        location / {
            status_zone $ssl_server_name zone=sni;
            return 200;
        }
    }

    server {
        listen %%PORT_8089%% ssl;
        server_name *.example.com;

        status_zone $ssl_server_cert_type zone=server_cert_type:2;

        ssl_protocols TLSv1.2;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        location / {
            status_zone $ssl_server_cert_type zone=server_cert_type:2;
            return 200;
        }
    }

    server {
        listen %%PORT_8090%% ssl;
        server_name *.example.com;

        status_zone $ssl_server_cert_type zone=server_cert_type:2;

        ssl_protocols TLSv1.2;

        ssl_certificate ecdsa.crt;
        ssl_certificate_key ecdsa.key;

        location / {
            status_zone $ssl_server_cert_type zone=server_cert_type:2;
            return 200;
        }
    }

    server {
        listen %%PORT_8093%% ssl;
        server_name *.example.com;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        status_zone $host zone=ssl_host:4;

        location / {
            status_zone off;
            return 200;
        }
    }

    map $http_user_agent $map_ssl_user_agent {
        volatile;
        "" handshakes;
        default $http_user_agent;
    }

    server {
        listen %%PORT_8094%% ssl;
        server_name *.example.com;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        status_zone $map_ssl_user_agent zone=map_ssl_user_agent:2;

        location / {
            return 200;
        }
    }

    server {
        listen %%PORT_8095%%;
        server_name *.example.com;

        status_zone $host zone=hosts:5;

        location / {
            status_zone $uri zone=uris:10;
            return 200;
        }

        location /loc1 {
            status_zone loc1;
            return 200;
        }

        location /loc2 {
            status_zone loc2;
            return 200;
        }
    }

    server {
        listen %%PORT_8096%%;

        location / {
            status_zone $uri zone=locations:10;
            return 200;
        }
    }

    server {
        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        server_name a.com;
        listen %%PORT_8097%% ssl;
        status_zone a;

        location / {
            return 200;
        }
    }

    server {
        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        server_name b.com;
        listen %%PORT_8097%% ssl;
        status_zone b;

        location / {
            return 200;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $tdir = $t->testdir();

system("openssl req -x509 -new -config $tdir/openssl.conf -subj /CN=rsa/ "
	. "-newkey rsa:2048 -keyout $tdir/rsa.key -out $tdir/rsa.crt "
	. "2>/dev/null") == 0
	or die "Can't create RSA certificate$!\n";

system("openssl ecparam -name secp384r1 -genkey -out $tdir/ecdsa.key "
	. "2>/dev/null") == 0
	or die "Can't create ECDSA key$!\n";

system("openssl req -new -config $tdir/openssl.conf "
	. "-subj /CN=ecdsa/ -key $tdir/ecdsa.key -x509 -nodes "
	. "-days 365 -out $tdir/ecdsa.crt 2>/dev/null") == 0
	or die "Can't create ECDSA certificate: $!\n";

$t->run();

my $a = 'a.example.com';
my $b = 'b.example.com';

###############################################################################

test_uri_zone();
test_locations_zone();
test_host_zone();
test_host_uri_zone();
test_single_zone();
test_sni_zone();
test_server_cert_type_zone();
test_ssl_host_zone();
test_ssl_user_agent_zone();
test_ssl_default_host_zone();

# Check all previous states
check_uri_zone();
check_locations_zone();
check_host_zone();
check_host_uri_zone();
check_single_zone();
check_sni_zone();
check_server_cert_type_zone();
check_ssl_host_zone();
check_ssl_user_agent_zone();
check_ssl_default_host_zone();

###############################################################################

sub check_stats_lz {
	my ($j, $count, $subname) = @_;

	is($j->{requests}{total}, $count, "$subname: requests total");
	is($j->{requests}{discarded}, 0, "$subname: requests discarded");

	if ($count == 0) {
		is($j->{data}{received}, 0, "$subname: data received");
		is($j->{data}{sent}, 0, "$subname: data sent");
		cmp_deeply($j->{responses}, {}, "$subname: responses");
	} else {
		ok($j->{data}{received} > 0, "$subname: data received");
		ok($j->{data}{sent} > 0, "$subname: data sent");
		cmp_deeply($j->{responses}, {200 => $count}, "$subname: responses");
	}
}

sub check_stats_sz {
	my ($j, $count, $subname) = @_;

	check_stats_lz($j, $count, $subname);

	is($j->{requests}{processing}, 0, "$subname: requests processing");
}

sub check_stats_sz_ssl {
	my ($j, $rcount, $hcount, $subname) = @_;

	check_stats_sz($j, $rcount, $subname);

	# 'ssl' section exists only in 'server_zones' section
	is($j->{ssl}{handshaked}, $hcount, "$subname: ssl handshaked");
	is($j->{ssl}{reuses}, 0, "$subname: ssl reuses");
	is($j->{ssl}{timedout}, 0, "$subname: ssl timedout");
	is($j->{ssl}{failed}, 0, "$subname: ssl failed");
}

sub check_ssl_host_zone {
	my $server_zones = get_json('/status/http/server_zones/');

	check_stats_sz_ssl($server_zones->{ssl_host}, 2, 0,
		"check 'ssl_host' server zone");

	check_stats_sz_ssl($server_zones->{'*.example.com'}, 0, 5,
		"check '*.example.com' server zone");

	for (1 .. 3) {
		my $host_zone = "$_.example.com";

		check_stats_sz_ssl($server_zones->{$host_zone}, 1, 0,
			"check '$host_zone' server zone");
	}
}

sub test_ssl_host_zone {
	for (1 .. 5) {
		get_host_ssl('/', 8093, "$_.example.com");
	}

	check_ssl_host_zone();
}

sub check_server_cert_type_zone {
	my $j = get_json('/status/http/');

	my $server_zones = $j->{server_zones};
	my $location_zones = $j->{location_zones};

	check_stats_sz_ssl($server_zones->{server_cert_type}, 0, 0,
		"check 'server_cert_type' server zone");

	check_stats_lz($location_zones->{server_cert_type}, 0,
		"check 'server_cert_type' location zone");

	check_stats_sz_ssl($server_zones->{RSA}, 2, 2, "check 'RSA' server zone");
	check_stats_sz_ssl($server_zones->{ECDSA}, 2, 2,
		"check 'ECDSA' server zone");

	check_stats_lz($location_zones->{RSA}, 2, "check 'RSA' location zone");
	check_stats_lz($location_zones->{ECDSA}, 2, "check 'ECDSA' location zone");
}

sub test_server_cert_type_zone {
	for (1 .. 2) {
		get_sni('/', 8089, 'localhost');
		get_sni('/', 8090, 'localhost');
	}

	check_server_cert_type_zone();
}

sub check_single_zone {
	my $j = get_json('/status/http/');

	check_stats_sz($j->{server_zones}{single}, 10,
		"check 'single' server zone");
	check_stats_lz($j->{location_zones}{single}, 10,
		"check 'single' location zone");

	$j = get_json('/status/http/server_zones/single');
	check_stats_sz($j, 10, "check 'single' server zone directly");

	$j = get_json('/status/http/location_zones/single');
	check_stats_lz($j, 10, "check 'single' location zone directly");
}

sub test_single_zone {
	for (1 .. 5) {
		get_host('/', 8085, 'localhost');
		get_host('/', 8086, 'localhost');
	}

	check_single_zone();
}

sub check_sni_zone {
	my $j = get_json('/status/');

	my $server_zones = $j->{http}{server_zones};
	my $location_zones = $j->{http}{location_zones};

	check_stats_sz_ssl($server_zones->{sni}, 10, 10, "check 'sni' server zone");
	check_stats_lz($location_zones->{sni}, 10, "check 'sni' location zone");

	for (1 .. 5) {
		my $a_zone = "$_.sni.$a";
		my $b_zone = "$_.sni.$b";

		check_stats_sz_ssl($server_zones->{$a_zone}, 2, 2,
			"check '$a_zone' server zone");
		check_stats_sz_ssl($server_zones->{$b_zone}, 2, 2,
			"check '$b_zone' server zone");

		ok(!exists $server_zones->{"f.$a_zone"},
			"'f.$a_zone' server zone does not exist");
		ok(!exists $server_zones->{"f.$b_zone"},
			"'f.$b_zone' server zone does not exist");

		check_stats_lz($location_zones->{$a_zone}, 2,
			"check '$a_zone' location zone");
		check_stats_lz($location_zones->{$b_zone}, 2,
			"check '$b_zone' location zone");

		ok(!exists $location_zones->{"f.$a_zone"},
			"'f.$a_zone' location zone does not exist");
		ok(!exists $location_zones->{"f.$b_zone"},
			"'f.$b_zone' location zone does not exist");
	}
}

sub test_sni_zone {
	for (1 .. 5) {
		get_sni('/', 8087, "$_.sni.$a");
		get_sni('/', 8088, "$_.sni.$b");
	}

	for (1 .. 5) {
		get_sni('/', 8087, "$_.sni.$a");
		get_sni('/', 8087, "f.$_.sni.$a");
		get_sni('/', 8088, "$_.sni.$b");
		get_sni('/', 8088, "f.$_.sni.$b");
	}

	check_sni_zone();
}

sub check_host_zone {
	my $j = get_json('/status/');

	my $server_zones = $j->{http}{server_zones};
	my $location_zones = $j->{http}{location_zones};

	check_stats_sz($server_zones->{a_host}, 5, "check 'a_host' server zone");
	check_stats_sz($server_zones->{b_host}, 5, "check 'b_host' server zone");

	check_stats_lz($location_zones->{a_host}, 5,
		"check 'a_host' location zone");
	check_stats_lz($location_zones->{b_host}, 5,
		"check 'b_host' location zone");

	for (1 .. 5) {
		my $a_zone = "$_.$a";
		my $b_zone = "$_.$b";

		my $zj = get_json("/status/http/server_zones/$a_zone");
		check_stats_sz($zj, 2, "check '$a_zone' server zone directly");

		$zj = get_json("/status/http/server_zones/$b_zone");
		check_stats_sz($zj, 2, "check '$b_zone' server zone directly");

		check_stats_sz($server_zones->{$a_zone}, 2,
			"check '$a_zone' server zone");
		check_stats_sz($server_zones->{$b_zone}, 2,
			"check '$b_zone' server zone");

		ok(!exists $server_zones->{"f.$a_zone"},
			"'f.$a_zone' server zone does not exist");
		ok(!exists $server_zones->{"f.$b_zone"},
			"'f.$b_zone' server zone does not exist");

		$zj = get_json("/status/http/location_zones/$a_zone");
		check_stats_lz($zj, 2, "check '$a_zone' location zone directly");

		$zj = get_json("/status/http/location_zones/$b_zone");
		check_stats_lz($zj, 2, "check '$b_zone' location zone directly");

		check_stats_lz($location_zones->{$a_zone}, 2,
			"check '$a_zone' location zone");
		check_stats_lz($location_zones->{$b_zone}, 2,
			"check '$b_zone' location zone");

		ok(!exists $location_zones->{"f.$a_zone"},
			"'f.$a_zone' location zone does not exist");
		ok(!exists $location_zones->{"f.$b_zone"},
			"'f.$b_zone' location zone does not exist");
	}
}

sub test_host_zone {
	for (1 .. 5) {
		get_host('/', 8084, "$_.$a");
		get_host('/', 8084, "$_.$b");
	}

	for (1 .. 5) {
		get_host('/', 8084, "$_.$a");
		get_host('/', 8084, "f.$_.$a");
		get_host('/', 8084, "$_.$b");
		get_host('/', 8084, "f.$_.$b");
	}

	check_host_zone();
}

sub check_uri_zone {
	my $j = get_json('/status/');

	my $server_zones = $j->{http}{server_zones};
	my $location_zones = $j->{http}{location_zones};

	check_stats_sz($server_zones->{uri}, 17, "check 'uri' server zone");
	check_stats_lz($location_zones->{uri}, 17, "check 'uri' location zone");

	for my $i (1 .. 5) {
		for my $j (1 .. 3) {
			check_stats_sz($server_zones->{"/$i.$j"}, 1,
				"check '/$i.$j' server zone");

			ok(!exists $server_zones->{"/$i.$j.f"},
				"'/$i.$j.f' server zone does not exist");

			check_stats_lz($location_zones->{"/$i.$j"}, 1,
				"check '/$i.$j' location zone");

			ok(!exists $location_zones->{"/$i.$j.f"},
				"'/$i.$j.f' location zone does not exist");
		}
	}
}

sub test_uri_zone {
	for my $i (1 .. 5) {
		for my $j (1 .. 3) {
			get_host("/$i.$j", 8080 + $j, 'localhost');
		}
	}

	for my $i (1 .. 5) {
		for my $j (1 .. 3) {
			get_host("/$i.$j.f", 8080 + $j, 'localhost');
		}
	}

	my $uri = '/' . ('a' x 254);

	for my $i (1 .. 3) {
		get_host($uri, 8081, 'localhost');
		$uri .= 'a';
	}

	check_uri_zone();
}

sub check_locations_zone {
	my $j = get_json('/status/');

	my $location_zones = $j->{http}{location_zones};

	check_stats_lz($location_zones->{locations}, 10,
		"check 'locations' location zone");

	for (1 .. 10) {
		check_stats_lz($location_zones->{"/location_$_"}, 2,
			"check 'location_$_' location zone");
	}

	for (11 .. 20) {
		ok(!exists $location_zones->{"/location_$_"},
			"'/location_$_' location zone does not exist");
	}
}

sub test_locations_zone {
	for (1 .. 20) {
		get_host("/location_$_", 8096, 'localhost');
	}

	for (1 .. 10) {
		get_host("/location_$_", 8096, 'localhost');
	}

	check_locations_zone();
}

sub check_host_uri_zone {
	my $j = get_json('/status/');

	my $server_zones = $j->{http}{server_zones};
	my $location_zones = $j->{http}{location_zones};

	check_stats_sz($server_zones->{hosts}, 0, "check 'hosts' server zone");
	check_stats_sz($server_zones->{localhost}, 10,
		"check 'localhost' server zone");
	check_stats_sz($server_zones->{$a}, 20, "check '$a' server zone");
	check_stats_sz($server_zones->{$b}, 20, "check '$b' server zone");

	check_stats_lz($location_zones->{uris}, 10, "check 'uris' location zone");
	check_stats_lz($location_zones->{loc1}, 10, "check 'loc1' location zone");
	check_stats_lz($location_zones->{loc2}, 10, "check 'loc2' location zone");

	for (1 .. 5) {
		check_stats_lz($location_zones->{"/loc_$_.1"}, 2,
			"check 'loc_/$_.1' location zone");
		check_stats_lz($location_zones->{"/loc_$_.2"}, 2,
			"check 'loc_/$_.2' location zone");

		ok(!exists $location_zones->{"/loc_$_.1.f"},
			"'/loc_$_.1.f' location zone does not exist");
		ok(!exists $location_zones->{"/loc_$_.2.f"},
			"'/loc_$_.2.f' location zone does not exist");
	}
}

sub test_host_uri_zone {
	for (1 .. 5) {
		get_host("/loc_$_.1", 8095, $a);
		get_host("/loc_$_.2", 8095, $a);

		get_host("/loc1", 8095, $a);
		get_host("/loc2", 8095, $a);
	}

	for (1 .. 5) {
		get_host("/loc_$_.1.f", 8095, $b);
		get_host("/loc_$_.2.f", 8095, $b);

		get_host("/loc1", 8095, $b);
		get_host("/loc2", 8095, $b);
	}

	for (1 .. 5) {
		get_host("/loc_$_.1", 8095, 'localhost');
		get_host("/loc_$_.2", 8095, 'localhost');
	}

	check_host_uri_zone();
}

sub check_ssl_user_agent_zone {
	my $user_agent_zone = get_json('/status/http/server_zones/user_agent/');

	check_stats_sz_ssl($user_agent_zone, 1, 0, "check 'user_agent' zone");
}

sub test_ssl_user_agent_zone {
	my $s = ssl_connect(8094);
	my $handshakes_zone = get_json('/status/http/server_zones/handshakes');

	check_stats_sz_ssl($handshakes_zone, 0, 1,
		"check 'handshakes' zone stats");

	$s->write("GET / HTTP/1.0\nUser-Agent: user_agent\n\n");
	like($s->read(), qr/200 OK/, 'correct response');

	check_ssl_user_agent_zone();
}

sub check_ssl_default_host_zone {
	my $j = get_json('/status/');

	my $a_zone = $j->{http}{server_zones}{a};
	my $b_zone = $j->{http}{server_zones}{b};

	check_stats_sz_ssl($a_zone, 1, 1, "check 'a' zone stats");
	check_stats_sz_ssl($b_zone, 1, 0, "check 'b' zone stats");
}

sub test_ssl_default_host_zone {
	my $s = ssl_connect(8097);

	my $server_zones = get_json('/status/http/server_zones/');

	my $a_zone = $server_zones->{a};
	my $b_zone = $server_zones->{b};

	check_stats_sz_ssl($a_zone, 0, 1, "check 'a' zone stats");
	check_stats_sz_ssl($b_zone, 0, 0, "check 'b' zone stats");

	$s->write("GET / HTTP/1.1\nHost: a.com\n\n");
	like($s->read(trailing_char => "$CRLF$CRLF"),
		qr/200 OK/, 'correct response - a.com');

	$s->write("GET / HTTP/1.1\nHost: b.com\n\n");
	like($s->read(trailing_char => "$CRLF$CRLF"),
		qr/200 OK/, 'correct response - b.com');

	check_ssl_default_host_zone();
}

###############################################################################

sub get_sni {
	my ($uri, $port, $sni) = @_;

	like(
		http_get(
			$uri,
			PeerAddr => '127.0.0.1',
			PeerPort => port($port),
			SSL => 1,
			SSL_hostname => $sni
		),
		qr/200 OK/,
		"request OK, uri '$uri', sni '$sni'"
	);
}

sub get_host_ssl {
	my ($uri, $port, $host) = @_;

	like(
		http(
			"GET $uri HTTP/1.0\nHost: $host\n\n",
			PeerAddr => '127.0.0.1',
			PeerPort => port($port),
			SSL => 1
		),
		qr/200 OK/,
		"request OK, uri '$uri', host '$host'"
	);
}

sub get_host {
	my ($uri, $port, $host) = @_;

	like(
		http(
			"GET $uri HTTP/1.0\nHost: $host\n\n",
			PeerAddr => '127.0.0.1',
			PeerPort => port($port)
		),
		qr/200 OK/,
		"request OK, uri '$uri', host '$host'"
	);
}

sub ssl_connect {
	my ($port) = @_;

	return stream(
		PeerAddr => '127.0.0.1',
		PeerPort => port($port),
		SSL => 1
	);
}

###############################################################################
