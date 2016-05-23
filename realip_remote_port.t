#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for realip_remote_port variable.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http realip ipv6 unix/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format port   $realip_remote_port;

    real_ip_header    X-Forwarded-For;
    set_real_ip_from  127.0.0.1/32;
    set_real_ip_from  ::1/128;

    server {
        listen       [::1]:8081;
        listen       unix:%%TESTDIR%%/unix.sock;

        location / {
            add_header X-Port $realip_remote_port;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            add_header X-Port $realip_remote_port;
        }

        location /log {
            add_header X-Port $realip_remote_port;
            access_log %%TESTDIR%%/port.log port;
        }

        location /inet6 {
            proxy_pass http://[::1]:8081/;
        }

        location /unix {
            proxy_pass http://unix:%%TESTDIR%%/unix.sock:/;
        }
    }
}

EOF

$t->write_file('index.html', '');
$t->write_file('log', '');
$t->try_run('no realip_remote_port')->plan(8);

###############################################################################

my ($sp, $data) = sp_get('/log');
like($data, qr/X-Port: $sp/, 'realip port');

like(http_get('/inet6'), qr/X-Port: \d+/, 'realip port inet6');

unlike(http_get('/unix'), qr/X-Port/, 'realip port unix');

# real_ip_header extract port

like(http_xff('/', '127.0.0.1:9080'), qr/X-Port: 9080/, 'xff');
unlike(http_xff('/', '127.0.0.1'), qr/X-Port/, 'xff - no port');
like(http_xff('/inet6', '[::1]:9081'), qr/X-Port: 9081/, 'xff - inet6');
unlike(http_xff('/inet6', '::1'), qr/X-Port/, 'xff - no port');

# log

$t->stop();

my $log = $t->read_file('/port.log');
chomp $log;

is($sp, $log, 'realip port log');

###############################################################################

sub http_xff {
	my ($uri, $xff) = @_;
	return http(<<EOF);
GET $uri HTTP/1.0
Host: localhost
X-Forwarded-For: $xff

EOF
}

sub sp_get {
	my $s = http_get(shift, start => 1);
	return ($s->sockport(),  http_end($s));
}

###############################################################################
