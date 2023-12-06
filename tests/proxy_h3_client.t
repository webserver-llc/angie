#!/usr/bin/perl

# (C) 2023 Web Server LLC

# Tests for HTTP/3 client basic functionality.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ $CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_start http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 proxy/)
	->has_daemon('openssl')->plan(50)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%


    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic default_server;
        server_name  h3backend;

        # some tests send big body, disable checks
        client_max_body_size 0;

        location / {
            add_header X-FOO FOO;
            add_header X-BAR BAR;
            add_header X-Connection $quic_connection;
            add_header X-Session "reuse=$ssl_session_reused";

            return 200 "OK server=$server_name;protocol=$http3";
        }

        location /post {
            # to have variable set, we need working proxy_pass,
            # so forward request to dummy backend

            add_header "X-BODY-1" $request_body;
            proxy_pass http://127.0.0.1:%%PORT_8888%%;
        }

        location /post_set_body {
            # to have variable set, we need working proxy_pass,
            # so forward request to dummy backend

            add_header "X-BODY-2" $request_body;
            proxy_pass http://127.0.0.1:%%PORT_8888%%;
        }

        location /post_nonbuf {
            # to have variable set, we need working proxy_pass,
            # so forward request to dummy backend

            add_header "X-BODY-3" $request_body;
            proxy_pass http://127.0.0.1:%%PORT_8888%%;
        }

        location /streaming_backend {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /methods {
            # verify we got method correctly
            add_header X-METHOD "$request_method";
            return 200 OK;
        }

        location /cookies {
            add_header X-Cookie "FOO=$cookie_foo BLAH=$cookie_blah";
            add_header Set-Cookie "one=AAA;two=BBB;Secure";
            return 200 OK;
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  vhost1;

        # some tests send big body, disable checks
        client_max_body_size 0;

        location / {
            return 200 "OK server=$server_name;protocol=$http3";
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  vhost2;

        # some tests send big body, disable checks
        client_max_body_size 0;

        location / {
            return 200 "OK server=$server_name;protocol=$http3";
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8900_UDP%% quic;
        server_name  h3backend2;

        ssl_reject_handshake on;
        location / {
            add_header X-Connection $quic_connection;
            return 200 "OK server=$server_name;protocol=$http3";
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:9901 quic;
        server_name  h3backend4;

        quic_retry on;

        location / {
            return 200 "OK server=$server_name;protocol=$http3";
        }
    }

    server {
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        listen       127.0.0.1:%%PORT_8903_UDP%% quic;
        server_name  hqbackend;

        http3_hq  on;

        location / {
            add_header X-Connection $quic_connection;
            return 200 "OK server=$server_name;protocol=$http3";
        }
    }

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    upstream u1 {
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    upstream u2 {
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    upstream usessions {
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    upstream uk {
        server 127.0.0.1:%%PORT_8999_UDP%%;

        keepalive          1;
        keepalive_requests 3;
    }

    upstream unext {
        server 127.0.0.1:%%PORT_8998_UDP%%;
        server 127.0.0.1:%%PORT_8999_UDP%%;
    }

    upstream uhs {
        server 127.0.0.1:%%PORT_8900_UDP%%;
    }

    upstream silent {
        server 127.0.0.1:%%PORT_8902_UDP%%;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;

            add_header X-BACKEND-FOO "ups-foo=$upstream_http_x_foo";
            add_header X-BACKEND-BAR "ups-bar=$upstream_http_x_bar";
        }

        location /cookies {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
        }

        location /proxyvar {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://$arg_uname;
        }

        location /proxyvar2 {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_method $arg_method;
            proxy_pass https://u/$arg_path;
        }

        location /sslinit {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_ssl_name                localhost;
            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate localhost.crt;

            # do not cache SSL sessions, so that ssl_init_bad test works

            proxy_pass https://u1;
        }

        location /sslinit_bad {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_ssl_name                example.com;
            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate localhost.crt;

            proxy_pass https://u2;
        }

        location /sessions {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://usessions;
        }

        location /host_key {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
            proxy_quic_host_key       "quic_host_key.dat";
        }

        client_header_timeout 1s;

        location /inline {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;
        }

        location /uk {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://uk;
        }

        location /unext {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://unext;

            add_header x-upstream_addr "$upstream_addr";
        }

        location /hs {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://uhs;
        }

        location /post {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
        }

        location /post_gso {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            # we are working with big body here
            proxy_busy_buffers_size    512k;
            proxy_buffers            4 512k;
            proxy_buffer_size          256k;

            proxy_quic_gso on;

            proxy_pass https://u;
        }

        location /post_set_body {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
            proxy_set_body "FooBar";
        }

        location /post_nonbuf {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
            proxy_request_buffering off;
        }

        location /streaming_backend {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://u;
            proxy_buffering off;
        }

        location /retry {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;

            proxy_pass https://127.0.0.1:9901;
        }

        location /trail {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;

            add_trailer X-T1 Foo1;
            add_trailer X-T2 Foo2;
        }

        location /trail_nonbuf {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;

            add_trailer X-T1 Foo1;
            add_trailer X-T2 Foo2;

            proxy_buffering off;
        }

        location /connect_timeout {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";
            proxy_connect_timeout 1s;

            proxy_pass https://silent;
        }

        location /early_client_error {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";
            proxy_connect_timeout 1s;

            # will trigger hardcoded error; TODO: remove when done
            proxy_quic_active_connection_id_limit 0;

            proxy_pass https://u;
        }

        location /bad_tp_error {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";
            proxy_connect_timeout 1s;

            # connection will fail to establish due to bad
            # transport parameter value
            proxy_quic_active_connection_id_limit 1;

            proxy_pass https://u;
        }

        location /hq {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;

            proxy_http_version "3";
            proxy_http3_hq on;

            proxy_pass https://127.0.0.1:%%PORT_8903_UDP%%;
        }

        location /vh1 {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;

            proxy_set_header "Host" "vhost1";
        }

        location /vh2 {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;

            proxy_set_header "Host" "vhost2";
        }

        location /vhvar {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version "3";

            proxy_pass https://127.0.0.1:%%PORT_8999_UDP%%;

            proxy_set_header "Host" $host;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8888%%;
        server_name  h3backend3;

        location / {
            return 200 "h3backend";
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

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('quic_host_key.dat', <<EOF);
SOMERANDOMSTRINGTGOUSEASAKEY
EOF

$t->run_daemon(\&http_daemon, port(8081));
$t->run_daemon(\&silent_udp_daemon, port(8902));

$t->run();

###############################################################################

my ($res, $n, $m);

my ($p1, $p2) = (port(8999), port(8998));

$res = http_get("/");

like($res, qr/HTTP\/1.1 200/, "response is 200");

like($res, "/server=h3backend;protocol=h3/", "backend response is using HTTP/3");
like($res, "/x-foo: FOO/", "header foo passed from upstream");
like($res, "/x-bar: BAR/", "header bar passed from upstream");
like($res, "/X-BACKEND-FOO: ups-foo=FOO/", "header foo set from upstream vars");
like($res, "/X-BACKEND-BAR: ups-bar=BAR/", "header bar set from upstream vars");

$res = http_cookies("/cookies");
like($res, "/x-cookie: FOO=bar BLAH=foobar/", "cookies passed to backend");
like($res, "/set-cookie: one=AAA;two=BBB/", "set-cookie passed from backend");

$res = http_get("/proxyvar?uname=u");
like($res, "/server=h3backend;protocol=h3/", "proxy_pass with variables");

$res = http_get("/host_key");

like($res, qr/HTTP\/1.1 200/, "response is 200 using host key");

$res = http_method("/methods", "HEAD");
like($res, "/HEAD/", "HEAD method OK");

$res = http_method("/methods", "POST");
like($res, "/POST/", "POST method OK");

$res = http_method("/methods", "DELETE");
like($res, "/DELETE/", "DELETE method OK");

$res = http_method("/methods", "PUT");
like($res, "/PUT/", "PUT method OK");

$res = http_method("/methods", "OPTIONS");
like($res, "/OPTIONS/", "OPTIONS method OK");

$res = http_method("/methods", "CUSTOM_NAME");
like($res, "/CUSTOM_NAME/", "CUSTOM_NAME method OK");

$res = http_get("/proxyvar2?method=FOO&path=/methods");
like($res, "/FOO/", "proxy pass with var path and method");

$res = http_get("/sslinit");
like($res, "/200/", "ssl verify with h3 - good name");

$res = http_get("/sslinit_bad");
like($res, "/502/", "ssl verify with h3 - bad name");

$res = http_get("/sessions");
like($res, "/x-session: reuse=\./", "ssl session reuse - request 1");

TODO: {

local $TODO = 'not supported in OpenSSL compat layer'
    unless $t->has_module('OpenSSL [.0-9]+\+quic')
        or $t->has_module('BoringSSL')
        or $t->has_module('LibreSSL');


    $res = http_get("/sessions");
    like($res, "/x-session: reuse=r/", "ssl session reuse - request 2");
}

# body test
$res = http_post("/post");
like($res, "/x-body-1: 1234567890/", "client body delivered to server");

$res = http_post("/post_set_body");
like($res, "/x-body-2: FooBar/", "proxy_set body delivered to server");

$res = http_post_chunks("/post_nonbuf");
like($res, "/x-body-3: abcdefghk/", "chunked body delivered to server");

$res = http_get("/streaming_backend");
like($res, "/abcdefghk/", "upstream non-buffered response");

# for GSO, we need some more data to trigger it
my $big_data = 'FOOBAR' x 1000;
$res = http_post_data("/post_gso", $big_data);
like($res, "/x-body-1: $big_data/", "data posted with GSO enabled");


$res = http_get("/uk");
($n) = $res =~ m/x-connection: (\d+)/;
like($res, "/server=h3backend;protocol=h3/", "h3 response 1 from ka upstream");


$res = http_get("/uk");
like($res, "/server=h3backend;protocol=h3/", "h3 response 2 from ka upstream");

($m) = $res =~ m/x-connection: (\d+)/;
is($n, $m, "request 2 using same connection: $m");

$res = http_get("/uk");
like($res, "/server=h3backend;protocol=h3/", "h3 response 3 from ka upstream");
($m) = $res =~ m/x-connection: (\d+)/;
is($n, $m, "request 3 using same connection: $m");


$res = http_get("/uk");
like($res, "/server=h3backend;protocol=h3/", "h3 response 4 from ka upstream");


($m) = $res =~ m/x-connection: (\d+)/;
isnt($n, $m, "request 4 using new connection: $m");


$res = http_get("/unext");
like($res, "/server=h3backend;protocol=h3/", "h3 response from backend");
like($res, "/x-upstream_addr: 127.0.0.1:$p2, 127.0.0.1:$p1/", "tried some servers before reply");

# use h3 config for implicit upstreams
$res = http_get("/inline");
like($res, "/server=h3backend;protocol=h3/", "h3 response from backend");

$res = http_get("/retry");
like($res, "/OK server=h3backend4;protocol=h3/", "HTTP/3 response from retry");

# for coverage: bad handshake
$res = http_get("/hs");
like($res, "/502 Bad Gateway/", "rejected handshake gives 502");

$res = http_get11("/trail");
like($res, qr/server=h3backend;protocol=h3${CRLF}0${CRLF}X-T1: Foo1${CRLF}X-T2: Foo2/, 'trailers added');

$res = http_get11("/trail_nonbuf");
like($res, qr/server=h3backend;protocol=h3${CRLF}0${CRLF}X-T1: Foo1${CRLF}X-T2: Foo2/, 'trailers added nonbuf');


$res = http_get("/connect_timeout");
like($res, "/504 Gateway Time-out/", "504 on connect timeout");

$res = http_get("/early_client_error");
like($res, "/500 Internal Server Error/", "500 on early error");

$res = http_get("/bad_tp_error");
like($res, "/502 Bad Gateway/", "502 on tp error");

$res = http09_get("/hq");
is($res, "OK server=hqbackend;protocol=hq", "response is HQ");


$res = http_get("/vh1");
like($res, "/server=vhost1;protocol=h3/", "selected virtual server 1");

$res = http_get("/vh2");
like($res, "/server=vhost2;protocol=h3/", "selected virtual server 2");

$res = http_host("/vhvar", "localhost");
like($res, "/server=h3backend;protocol=h3/", "selected default server");

$res = http_host("/vhvar", "vhost1");
like($res, "/server=vhost1;protocol=h3/", "selected virtual server 1 via var");

$res = http_host("/vhvar", "vhost2");
like($res, "/server=vhost2;protocol=h3/", "selected virtual server 2 via var");

$res = http09_get("/vh1");
like($res, "/server=vhost1;protocol=h3/", "selected virtual server 1 via 09");

###############################################################################

sub http_method {
	my ($uri, $method) = @_;
	http(<<EOF);
$method $uri HTTP/1.1
Host: localhost
Connection: close

EOF
}


sub http_host {
	my ($uri, $host) = @_;
	http(<<EOF);
GET $uri HTTP/1.1
Connection: close
Host: $host

EOF
}


sub http09_get {
	my ($uri) = @_;
	http(<<EOF);
GET $uri

EOF
}

sub http_cookies {
	my ($uri) = @_;
	http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
Cookie: foo=bar;baz=dar;blah=foobar

EOF
}

sub http_post {
	my ($uri) = @_;
	http(<<EOF);
POST $uri HTTP/1.0
Host: localhost
Content-Length: 10

1234567890
EOF
}

sub http_post_data {
	my ($uri, $data) = @_;
	my $len = length($data);
	http(<<EOF);
POST $uri HTTP/1.0
Host: localhost
Content-Length: $len

$data
EOF
}

sub send_chunks {
    my ($sock, $delay) = @_;
    $sock->write(<<EOF);
3
abc
EOF

select(undef, undef, undef, $delay);
    $sock->write(<<EOF);
4
defg
EOF

select(undef, undef, undef, $delay);

    $sock->write(<<EOF);
2
hk
0

EOF
}

sub http_post_chunks {
	my ($uri) = @_;

# note: connection:close is needed, because otherwise client does not
# read server's reply
	my $request = <<EOF;
POST $uri HTTP/1.1
Host: localhost
Connection: close
Transfer-Encoding: chunked

EOF

	my $s = http_start($request);

	$s->write(<<EOF);
3
abc
EOF

	$s->write(<<EOF);
4
defg
EOF

# insert delay before the last chunk to trigger chunked output filter
select(undef, undef, undef, 1);

	$s->write(<<EOF);
2
hk
0

EOF
	return http_end($s);
}

sub http_daemon {
	my ($port) = @_;
	my $count = 1;

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

		print $client <<EOF;
HTTP/1.1 200 OK
Transfer-Encoding: chunked

EOF
		send_chunks($client, 1);

		close $client;
	}
}

sub silent_udp_daemon {
	my ($port) = @_;
	my $count = 1;

	my $socket = IO::Socket::INET->new(
		Proto => 'udp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my $recv_data;
	# drop silently everything
	while (1) {
		$socket->recv($recv_data, 65536);
	}
}

sub http_get11 {
	my ($uri) = @_;
	http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close

EOF
}

