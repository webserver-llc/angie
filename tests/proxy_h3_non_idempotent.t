#!/usr/bin/perl

# (C) 2023 Web Server LLC
# (C) Maxim Dounin
# (C) Nginx, Inc.

# Tests for proxy_next_upstream non_idempotent.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/:DEFAULT http_post/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http proxy rewrite upstream_keepalive http_v3/)
	->has_daemon("openssl")
	->plan(12);

$t->prepare_ssl();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=0;
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=0;
    }

    upstream uk {
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=0;
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=0;
        keepalive 10;
    }

    upstream uc {
        server 127.0.0.1:%%PORT_8998_UDP%% max_fails=0;  # nobody should listen on it
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=0;
    }

    upstream uf {
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=1 fail_timeout=1m;
        server 127.0.0.1:%%PORT_8997_UDP%% max_fails=1 fail_timeout=1m;
    }

    upstream uf_retry {
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=1 fail_timeout=1m;
        server 127.0.0.1:%%PORT_8997_UDP%% max_fails=1 fail_timeout=1m;
    }

    upstream uf_recover {
        server 127.0.0.1:%%PORT_8999_UDP%% max_fails=1 fail_timeout=2s;
        server 127.0.0.1:%%PORT_8997_UDP%% max_fails=1 fail_timeout=2s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-IP $upstream_addr always;

        location / {
            proxy_pass https://u;
            proxy_http_version  3;

            proxy_next_upstream error timeout http_404;
        }

        location /non {
            proxy_pass https://u;
            proxy_http_version  3;
            proxy_next_upstream error timeout non_idempotent;
        }

        location /keepalive {
            proxy_pass https://uk;
            proxy_http_version  3;
            proxy_next_upstream error timeout;
            proxy_set_header Connection "";
        }

        location /conn {
            proxy_pass https://uc;
            proxy_http_version  3;
        }

        location /fail {
            proxy_pass https://uf;
            proxy_http_version  3;
            proxy_next_upstream error timeout http_404;
        }

        location /fail_retry {
            proxy_pass https://uf_retry;
            proxy_http_version  3;
            proxy_next_upstream error timeout non_idempotent;
        }

        location /fail_recover {
            proxy_pass https://uf_recover;
            proxy_http_version  3;
            proxy_next_upstream error timeout http_404;
        }
    }

    server {
        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        listen       127.0.0.1:%%PORT_8999_UDP%% quic;
        server_name  localhost;

        location / {
            return 444;
        }

        location /404
                 /conn
        {
            return 404 SEE-THIS;
        }

        location /keepalive/establish {
            return 204;
        }
    }

    server {
        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        listen       127.0.0.1:%%PORT_8997_UDP%% quic;
        server_name  localhost;

        location /404
                 /fail
        {
            return 404 SEE-THIS;
        }

        location /fail_retry {
            return 444;
        }
    }
}

EOF

$t->run();

###############################################################################

# non-idempotent requests should not be retried by default
# if a request has been sent to a backend

like(http_get('/'), qr/X-IP: (\S+), \1\x0d?$/m, 'get');
like(http_post('/'), qr/X-IP: (\S+)\x0d?$/m, 'post');

# emit builtin error page both for the idempotent requests that try next
# upstream and for non-idempotent requests that stop processing on first
# failure

unlike(http_get('/404'), qr/X-IP: (\S+), \1.*SEE-THIS/s, 'get 404');
unlike(http_post('/404'), qr/X-IP: (\S++)(?! ).*SEE-THIS/s, 'post 404');

# with "proxy_next_upstream non_idempotent" there is no
# difference between idempotent and non-idempotent requests,
# non-idempotent requests are retried as usual

like(http_get('/non'), qr/X-IP: (\S+), \1\x0d?$/m, 'get non_idempotent');
like(http_post('/non'), qr/X-IP: (\S+), \1\x0d?$/m, 'post non_idempotent');

# cached connections follow the same rules

like(http_get('/keepalive/establish'), qr/204 No Content/m, 'keepalive');
like(http_post('/keepalive/drop'), qr/X-IP: (\S+)\x0d?$/m, 'keepalive post');

like(http_post('/conn'), qr/X-IP: \S+, \S+.*SEE-THIS/s, 'post conn failed');

subtest 'non-idempotent request marks peer' => sub {
	# non-idempotent request against a failing upstream should still
	# mark the responding peer's status via the error path
	# (ngx_http_upstream_next -> free_peer), even though the request
	# itself is not retried

	my $r1 = http_post('/fail');
	unlike($r1, qr/SEE-THIS.*SEE-THIS/s, 'post fail single attempt');

	$r1 =~ /X-IP: (\S+)/;
	my $failed_peer = $1;
	ok(defined $failed_peer, 'failed peer captured');

	# a following idempotent GET (with proxy_next_upstream) should retry
	# across both peers in the upstream; if the first peer was correctly
	# marked failed, it should be skipped due to max_fails/fail_timeout
	# and GET must be routed to the surviving good peer

	my $r2 = http_get('/fail');
	unlike($r2, qr/X-IP:[^\r\n]*\Q$failed_peer\E/,
		'failed peer skipped on retry');

	my @peers = $r2 =~ /X-IP: (.+)/g;
	my @addrs = split /,\s*/, $peers[0];

	ok((grep { $_ ne $failed_peer } @addrs),
		'GET directed to non-failed peer');
};

subtest 'POST non_idempotent retried across both peers' => sub {
	# with "non_idempotent" explicitly allowed in proxy_next_upstream,
	# a POST is retried across both peers, marking both
	# as failed after a single request

	like(http_post('/fail_retry'), qr/X-IP: \S+, \S+/s,
		'post non_idempotent retried across both peers');

	# both peers should be skipped after the immediately following
	# non idempotent GET - both peers are failed
	my $r = http_get('/fail_retry');
	like($r, qr/X-IP: uf_retry\x0d?$/m,
		'both peers skipped after non_idempotent retry');
	like($r, qr/502 Bad Gateway/,
		'both peers marked failed after non_idempotent retry');
};

subtest 'peer recovering after fail_timeout' => sub {
	my $p1 = port(8999, udp => 1);

	# mark 8999 as failed (POST -> 444 -> error path -> free_peer)
	http_post('/fail_recover');

	# 8999 must be skipped as failed, the request routes only to 8997
	unlike(http_get('/fail_recover'), qr/127\.0\.0\.1:$p1/,
		'failed peer skipped before fail_timeout');

	# wait out fail_timeout=2s
	select undef, undef, undef, 3;

	# 8999 eligible again
	# (8999 -> 444 -> error -> retry -> 8997)
	like(http_get('/fail_recover'), qr/127\.0\.0\.1:$p1/,
		'peer eligible again after fail_timeout');
};

###############################################################################

###############################################################################
