#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http proxy_bind transparent.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_primary_user_group/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'must be root') if $> != 0;
plan(skip_all => '127.0.0.2 local address required')
	unless defined IO::Socket::INET->new( LocalAddr => '127.0.0.2' );

my $primary_root_group = get_primary_user_group('root');
plan(skip_all => 'cannot determine primary group of root')
	unless defined $primary_root_group;

my $t = Test::Nginx->new({can_root => 1})
	->has(qw/http proxy transparent_proxy/)
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;
user root $primary_root_group;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen          127.0.0.1:8080;
        server_name     localhost;

        location / {
            proxy_bind  127.0.0.2 transparent;
            proxy_pass  http://127.0.0.1:8081/;
        }
    }

    server {
        listen          127.0.0.1:8081;
        server_name     localhost;

        location / {
            add_header   X-IP \$remote_addr always;
        }
    }
}

EOF

$t->run()->plan(1);

###############################################################################

like(http_get('/'), qr/X-IP: 127.0.0.2/, 'transparent');

###############################################################################
