#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for stream 'status_zone' directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http_api stream stream_ssl_preread/)
	->has(qw/stream_ssl stream_return stream_map socket_ssl_sni stream_pass/)
	->has(qw/rewrite sni/)
	->has_daemon('openssl')->plan(2138)
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
        listen %%PORT_8094%%;

        location / {
            return 200;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen %%PORT_8081%%;

        status_zone $remote_addr zone=remote_addr;

        return OK;
    }

    server {
        listen %%PORT_8082%%;

        status_zone $remote_addr zone=remote_addr;

        return OK;
    }

    server {
        listen %%PORT_8083%%;

        status_zone $remote_addr zone=remote_addr:30;

        return OK;
    }

    server {
        listen %%PORT_8084%% ssl;
        server_name *.a.example.com;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        ssl_protocols TLSv1.2;

        status_zone $ssl_server_name zone=sni:15;

        return OK;
    }

    server {
        listen %%PORT_8084%% ssl;
        server_name *.b.example.com;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        ssl_protocols TLSv1.2;

        status_zone $ssl_server_name zone=sni;

        return OK;
    }

    map $ssl_server_name $sni_map_zone {
        volatile;
        "" sni;
        default $ssl_server_name;
    }

    server {
        listen %%PORT_8084%% ssl;
        server_name *.c.example.com;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        ssl_protocols TLSv1.2;

        status_zone $sni_map_zone zone=sni;

        return OK;
    }

    server {
        listen %%PORT_8085%% ssl;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        status_zone cert_$ssl_server_cert_type zone=server_cert_type:3;

        return OK;
    }

    server {
        listen %%PORT_8086%% ssl;

        ssl_certificate ecdsa.crt;
        ssl_certificate_key ecdsa.key;

        status_zone cert_$ssl_server_cert_type zone=server_cert_type:3;

        return OK;
    }

    map $ssl_preread_server_name $preread_name{
        volatile;
        *.example.com u;
        default 127.0.0.1:8090;
    }

    upstream u {
        server 127.0.0.1:8089;
    }

    server {
        listen %%PORT_8087%%;

        status_zone host_$ssl_preread_server_name zone=sni_preread:5;
        ssl_preread on;

        proxy_pass $preread_name;
    }

    server {
        listen %%PORT_8088%%;

        status_zone $ssl_preread_server_name zone=sni_preread;
        ssl_preread on;

        proxy_pass $preread_name;
    }

    server {
        listen %%PORT_8089%% ssl;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        return "OK";
    }

    server {
        listen %%PORT_8090%% ssl;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        return "OK";
    }

    server {
        listen %%PORT_8093%% ssl;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        status_zone $ssl_server_name zone=sni_pass:10;

        pass 127.0.0.1:8094;
    }

    server {
        listen %%PORT_8095%% ssl;

        ssl_certificate rsa.crt;
        ssl_certificate_key rsa.key;

        status_zone pfx.$ssl_server_name zone=long:3;

        return "OK";
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

my $a = "a.example.com";
my $b = "b.example.com";
my $c = "c.example.com";

# 251 bytes
my $long_sni = (('a' x 60) . '.') x 4 . 'a' x 7;

###############################################################################

SKIP: {
	skip 'OS is not linux', 492 if $^O ne 'linux';
	test_remote_addr_zone();
}

test_sni_zone();
test_server_cert_type_zone();
test_sni_preread_zone();
test_sni_pass_zone();
test_long_zone();

# Check all previous states
SKIP: {
	skip 'OS is not linux', 402 if $^O ne 'linux';
	check_remote_addr_zone();
}

check_sni_zone();
check_server_cert_type_zone();
check_sni_preread_zone();
check_sni_pass_zone();
check_long_zone();

###############################################################################

sub check_stats_base {
	my ($j, $count, $subname) = @_;

	is($j->{connections}{total}, $count, "$subname: connections total");
	is($j->{connections}{processing}, 0, "$subname: connections processing");
	is($j->{connections}{discarded}, 0, "$subname: connections discarded");

	is($j->{sessions}{invalid}, 0, "$subname: sessions invalid");
	is($j->{sessions}{forbidden}, 0, "$subname: sessions forbidden");
	is($j->{sessions}{internal_error}, 0, "$subname: sessions internal_error");
	is($j->{sessions}{bad_gateway}, 0, "$subname: sessions bad_gateway");
	is($j->{sessions}{service_unavailable}, 0,
		"$subname: sessions service_unavailable");

	ok($j->{data}{sent} >= 0, "$subname: data sent");
	ok($j->{data}{received} >= 0, "$subname: data received");
}

sub check_stats {
	my ($j, $count, $subname) = @_;

	check_stats_base($j, $count, $subname);
	is($j->{sessions}{success}, $count, "$subname: sessions success");
	is($j->{connections}{passed}, 0, "$subname: connections passed");
}

sub check_stats_ssl_base {
	my ($j, $count, $subname) = @_;

	is($j->{ssl}{handshaked}, $count, "$subname: ssl handshaked");
	is($j->{ssl}{reuses}, 0, "$subname: ssl reuses");
	is($j->{ssl}{timedout}, 0, "$subname: ssl timeout");
	is($j->{ssl}{failed}, 0, "$subname: ssl failed");
}

sub check_stats_ssl_pass {
	my ($j, $count, $subname) = @_;

	check_stats_base($j, $count, $subname);
	check_stats_ssl_base($j, $count, $subname);
	is($j->{connections}{passed}, $count, "$subname: connections passed");
	is($j->{sessions}{success}, 0, "$subname: sessions success");
}

sub check_stats_ssl {
	my ($j, $count, $subname) = @_;

	check_stats($j, $count, $subname);
	check_stats_ssl_base($j, $count, $subname);
}

sub check_sni_pass_zone {
	my $server_zones = get_json('/status/stream/server_zones/');

	check_stats_ssl_pass($server_zones->{sni_pass}, 0,
		"check 'sni_pass' zone");

	for (1 .. 2) {
		check_stats_ssl_pass($server_zones->{$a}, 2, "check '$a' zone");
		check_stats_ssl_pass($server_zones->{$b}, 2, "check '$b' zone");
	}
}

sub test_sni_pass_zone {
	for (1 .. 2) {
		https_get(8093, $a);
		https_get(8093, $b);
	}

	check_sni_pass_zone();
}

sub check_server_cert_type_zone {
	my $server_zones = get_json('/status/stream/server_zones/');

	check_stats_ssl($server_zones->{server_cert_type}, 0,
		"check 'server_cert_type' zone");
	check_stats_ssl($server_zones->{cert_}, 0, "check 'cert_' zone");

	check_stats_ssl($server_zones->{cert_RSA}, 2, "check 'cert_RSA' zone");
	check_stats_ssl($server_zones->{cert_ECDSA}, 2, "check 'cert_ECDSA' zone");

	check_stats_ssl($server_zones->{cert_RSA}, 2, "check 'cert_RSA' zone");
	check_stats_ssl($server_zones->{cert_ECDSA}, 2, "check 'cert_ECDSA' zone");

	my $j = get_json('/status/stream/server_zons/cert_RSA');
	check_stats_ssl($server_zones->{cert_RSA}, 2,
		"check 'cert_RSA' zone directly");

	$j = get_json('/status/stream/server_zons/cert_ECDSA');
	check_stats_ssl($server_zones->{cert_ECDSA}, 2,
		"check 'cert_ECDSA' zone directly");
}

sub test_server_cert_type_zone {
	for (1 .. 2) {
		stream_ssl_request(8085, 'localhost');
		stream_ssl_request(8086, 'localhost');
	}

	check_server_cert_type_zone();
}

sub check_sni_preread_zone {
	my $server_zones = get_json('/status/stream/server_zones/');

	check_stats($server_zones->{sni_preread}, 4, "check 'sni_preread' zone");
	check_stats($server_zones->{host_}, 0, "check 'host_' zone");

	for (1 .. 2) {
		my $a_zone = "host_preread.$_.$a";
		my $b_zone = "preread.$_.$b";

		check_stats($server_zones->{$a_zone}, 2, "check '$a_zone' zone");
		check_stats($server_zones->{$b_zone}, 2, "check '$b_zone' zone");

		ok(!exists $server_zones->{"$a_zone.f"},
			"'$a_zone.f' zone does not exist");
		ok(!exists $server_zones->{"$b_zone.f"},
			"'$b_zone.f' zone does not exist");
	}
}

sub test_sni_preread_zone {
	for (1 .. 2) {
		stream_ssl_request(8087, "preread.$_.$a");
		stream_ssl_request(8088, "preread.$_.$b");
	}

	for (1 .. 2) {
		stream_ssl_request(8087, "preread.$_.$a.f");
		stream_ssl_request(8087, "preread.$_.$b.f");
	}

	for (1 .. 2) {
		stream_ssl_request(8087, "preread.$_.$a");
		stream_ssl_request(8088, "preread.$_.$b");
	}

	check_sni_preread_zone();
}

sub check_sni_zone {
	my $server_zones = get_json('/status/stream/server_zones/');

	check_stats_ssl($server_zones->{sni}, 15, "check 'sni' zone'");

	for (1 .. 5) {
		my $a_zone = "$_.$a";
		my $b_zone = "$_.$b";
		my $c_zone = "$_.$c";

		check_stats_ssl($server_zones->{$a_zone}, 2, "check '$a_zone' zone");
		check_stats_ssl($server_zones->{$b_zone}, 2, "check '$b_zone' zone");
		check_stats_ssl($server_zones->{$c_zone}, 2, "check '$c_zone' zone");

		ok(!exists $server_zones->{"f.$a_zone"},
			"'f.$a_zone' zone does not exist");
		ok(!exists $server_zones->{"f.$b_zone"},
			"'f.$b_zone' zone does not exist");
		ok(!exists $server_zones->{"f.$c_zone"},
			"'f.$c_zone' zone does not exist");
	}
}

sub test_sni_zone {
	for (1 .. 5) {
		stream_ssl_request(8084, "$_.$a");
		stream_ssl_request(8084, "$_.$b");
		stream_ssl_request(8084, "$_.$c");
	}

	for (1 .. 5) {
		stream_ssl_request(8084, "f.$_.$a");
		stream_ssl_request(8084, "f.$_.$b");
		stream_ssl_request(8084, "f.$_.$c");
	}

	for (1 .. 5) {
		stream_ssl_request(8084, "$_.$a");
		stream_ssl_request(8084, "$_.$b");
		stream_ssl_request(8084, "$_.$c");
	}

	check_sni_zone();
}

sub check_long_zone {
	my $server_zones = get_json('/status/stream/server_zones/');
	my $zone = 'pfx.' . $long_sni;

	for (1 .. 2) {
		check_stats_ssl($server_zones->{$zone}, 1, "check '$zone' zone");

		$zone .= 'a';
	}

	ok(!exists $server_zones->{$zone}, "'$zone' zone does not exist");
}

sub test_long_zone {
	my $sni = $long_sni;

	for (1 .. 3) {
		stream_ssl_request(8095, $sni);
		$sni .= 'a';
	}

	check_long_zone();
}

sub check_remote_addr_zone {
	my $server_zones = get_json('/status/stream/server_zones/');

	check_stats($server_zones->{remote_addr}, 30, "check 'remote_addr' zone");

	for (1 .. 10) {
		check_stats($server_zones->{"127.0.1.$_"}, 2,
			"check '127.0.1.$_' zone");
		check_stats($server_zones->{"127.0.2.$_"}, 2,
			"check '127.0.2.$_' zone");
		check_stats($server_zones->{"127.0.3.$_"}, 2,
			"check '127.0.3.$_' zone");

		ok(!exists $server_zones->{"127.1.1.$_"},
			"'127.1.1.$_' zone does not exist");
		ok(!exists $server_zones->{"127.1.2.$_"},
			"'127.1.2.$_' zone does not exist");
		ok(!exists $server_zones->{"127.1.3.$_"},
			"'127.1.3.$_' zone does not exist");
	}
}

sub test_remote_addr_zone {
	for (1 .. 10) {
		stream_request(8081, "127.0.1.$_");
		stream_request(8082, "127.0.2.$_");
		stream_request(8083, "127.0.3.$_");
	}

	for (1 .. 10) {
		stream_request(8081, "127.1.1.$_");
		stream_request(8082, "127.1.2.$_");
		stream_request(8083, "127.1.3.$_");
	}

	for (1 .. 10) {
		stream_request(8081, "127.0.1.$_");
		stream_request(8082, "127.0.2.$_");
		stream_request(8083, "127.0.3.$_");
	}

	check_remote_addr_zone();
}

sub stream_ssl_request {
	my ($port, $sni) = @_;

	my $s = stream(
		PeerAddr => '127.0.0.1',
		PeerPort => port($port),
		SSL => 1,
		SSL_hostname => $sni
	);

	like($s->read(), qr/OK/, "ssl connect OK, sni '$sni'");
}

sub stream_request {
	my ($port, $local_addr) = @_;

	my $s = stream(
		PeerAddr => '127.0.0.1',
		PeerPort => port($port),
		LocalAddr => $local_addr
	);

	like($s->read(), qr/OK/, "connect OK from $local_addr");
}

sub https_get {
	my ($port, $sni) = @_;

	like(
		http_get(
			'/',
			PeerAddr => '127.0.0.1',
			PeerPort => port($port),
			SSL => 1,
			SSL_hostname => $sni
		),
		qr/200 OK/,
		"request OK, sni '$sni'"
	);
}

###############################################################################
