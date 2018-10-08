#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http mirror module and it's interaction with proxy.

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

my $t = Test::Nginx->new()->has(qw/http proxy mirror rewrite limit_req/);

$t->write_file_expand('nginx.conf', <<'EOF')->plan(7);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_req_zone  $uri  zone=slow:1m  rate=30r/m;
    log_format  test  $request_uri:$request_body;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            mirror /mirror;
            proxy_pass http://127.0.0.1:8081;
        }

        location /off {
            mirror /mirror/off;
            mirror_request_body off;
            proxy_pass http://127.0.0.1:8081;
        }

        location /mirror {
            internal;
            proxy_pass http://127.0.0.1:8082;
            limit_req  zone=slow burst=1;
        }
    }

    server {
        listen       127.0.0.1:8081;
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            client_body_timeout 1s;
            proxy_pass http://127.0.0.1:$server_port/return204;
            access_log %%TESTDIR%%/test.log test;
            add_header X-Body $request_body;
        }

        location /return204 {
            return 204;
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_post('/'), qr/X-Body: 1234567890\x0d?$/m, 'mirror proxy');
like(http_post('/off'), qr/X-Body: 1234567890\x0d?$/m, 'mirror_request_body');

# delayed subrequest should not affect main request processing nor stuck itself

SKIP: {
skip 'hang on win32', 1 if $^O eq 'MSWin32' and !$ENV{TEST_NGINX_UNSAFE};

TODO: {
local $TODO = 'not yet';

like(http_post('/delay?1'), qr/X-Body: 1234567890\x0d?$/m, 'mirror delay');

}

}

$t->todo_alerts() unless $^O eq 'MSWin32';
$t->stop();

my $log = $t->read_file('test.log');
like($log, qr!^/:1234567890$!m, 'log - request body');
like($log, qr!^/mirror:1234567890$!m, 'log - request body in mirror');
like($log, qr!^/off:1234567890$!m, 'log - mirror_request_body off');
like($log, qr!^/mirror/off:-$!m,, 'log - mirror_request_body off in mirror');

###############################################################################

sub http_post {
	my ($url) = @_;

	http(<<EOF);
POST $url HTTP/1.0
Host: localhost
Content-Length: 10

1234567890
EOF
}

###############################################################################
