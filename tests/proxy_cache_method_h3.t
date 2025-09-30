#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for http proxy cache with proxy_method and http3.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 proxy cache/)
	->has_daemon('openssl')->plan(24)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=kz:1m;

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;

        location /on {
            proxy_http_version 3;
            proxy_pass https://127.0.0.1:%%PORT_8981_UDP%%/;
            proxy_cache           kz;
            proxy_cache_valid     any 1m;
            proxy_cache_min_uses  1;

            proxy_method $arg_method;
            #proxy_cache_convert_head on; # "on" is default

            add_header X-Upstream-Method $upstream_request_method;
        }

        location /off {
            proxy_http_version 3;
            proxy_pass https://127.0.0.1:%%PORT_8981_UDP%%/;
            proxy_cache           kz;
            proxy_cache_valid     any 1m;
            proxy_cache_min_uses  1;

            proxy_method $arg_method;
            proxy_cache_convert_head off;

            add_header X-Upstream-Method $upstream_request_method;
        }

    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;
        location / {
            add_header X-Method $request_method;
        }
    }
}

EOF

$t->prepare_ssl();

my $d = $t->testdir();

$t->write_file('t1.html', 'SEE-THIS');
$t->write_file('t2.html', 'SEE-THIS');
$t->write_file('t3.html', 'SEE-THIS');
$t->write_file('t4.html', 'SEE-THIS');

$t->write_file('t5.html', 'SEE-THIS');
$t->write_file('t6.html', 'SEE-THIS');
$t->write_file('t7.html', 'SEE-THIS');
$t->write_file('t8.html', 'SEE-THIS');


$t->run();

###############################################################################

my ($h, $b);

($h, $b) = http3_req('/on/t1.html?method=GET', 'GET');
is($h->{'x-method'}, 'GET', 'GET->GET on');
is($h->{'x-upstream-method'}, 'GET', '$upstream_request_method is GET');
is($b, 'SEE-THIS', 'proxy request body ok');

($h, $b) = http3_req('/on/t2.html?method=HEAD', 'GET');
is($h->{'x-method'}, 'HEAD', 'GET->HEAD on');
is($h->{'x-upstream-method'}, 'HEAD', '$upstream_request_method is HEAD');
unlike($b, qr/SEE-THIS/, 'proxy request no body');

($h, $b) = http3_req('/on/t3.html?method=GET', 'HEAD');
is($h->{'x-method'}, 'GET', 'HEAD->GET on');
is($h->{'x-upstream-method'}, 'GET', '$upstream_request_method is GET');
unlike($b, qr/SEE-THIS/, 'proxy request no body');

($h, $b) = http3_req('/on/t4.html?method=HEAD', 'HEAD');
is($h->{'x-method'}, 'HEAD', 'HEAD->HEAD on');
is($h->{'x-upstream-method'}, 'HEAD', '$upstream_request_method is HEAD');
unlike($b, qr/SEE-THIS/, 'proxy request no body');

($h, $b) = http3_req('/off/t5.html?method=GET', 'GET');
is($h->{'x-method'}, 'GET', 'GET->GET off');
is($h->{'x-upstream-method'}, 'GET', '$upstream_request_method is GET');
like($b, qr/SEE-THIS/, 'proxy request body ok');

($h, $b) = http3_req('/off/t6.html?method=HEAD', 'GET');
is($h->{'x-method'}, 'HEAD', 'GET->HEAD off');
is($h->{'x-upstream-method'}, 'HEAD', '$upstream_request_method is HEAD');
unlike($b, qr/SEE-THIS/, 'proxy request no body');

($h, $b) = http3_req('/off/t7.html?method=GET', 'HEAD');
is($h->{'x-method'}, 'GET', 'HEAD->GET off');
is($h->{'x-upstream-method'}, 'GET', '$upstream_request_method is GET');
unlike($b, qr/SEE-THIS/, 'proxy request no body');

($h, $b) = http3_req('/off/t8.html?method=HEAD', 'HEAD');
is($h->{'x-method'}, 'HEAD', 'HEAD->HEAD off');
is($h->{'x-upstream-method'}, 'HEAD', '$upstream_request_method is HEAD');
unlike($b, qr/SEE-THIS/, 'proxy request no body');


###############################################################################

sub http3_req {
	my ($uri, $method) = @_;
	my ($s, $hdr, $sid, $frames, $frame, $body);

	$s = Test::Nginx::HTTP3->new();
	$sid = $s->new_stream({ headers => [
		{ name => ':method', value => $method, mode => 0 },
		{ name => ':scheme', value => 'http', mode => 0 },
		{ name => ':path', value =>  $uri, mode => 4 },
		{ name => ':authority', value => 'localhost', mode => 4 }]});
	$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

	($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
	$hdr = $frame->{headers};

	$body = join '', map { $_->{data} } grep { $_->{type} eq "DATA" } @$frames;

	return $hdr, $body;
}

###############################################################################
