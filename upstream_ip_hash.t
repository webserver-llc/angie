#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for upstream ip_hash balancer.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy upstream_ip_hash realip rewrite/)
	->write_file_expand('nginx.conf', <<'EOF')->run();

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        ip_hash;
        server 127.0.0.1:%%PORT_1%%;
        server 127.0.0.1:%%PORT_2%%;
    }

    upstream u2 {
        ip_hash;
        server 127.0.0.1:%%PORT_1%%;
        server 127.0.0.1:%%PORT_2%%;
        server 127.0.0.1:%%PORT_3%%;
    }

    server {
        listen       127.0.0.1:%%PORT_0%%;
        server_name  localhost;

        set_real_ip_from 127.0.0.0/8;
        add_header X-IP $remote_addr;

        location / {
            proxy_pass http://u;
        }
        location /u2 {
            proxy_pass http://u2;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_1%%;
        listen       127.0.0.1:%%PORT_2%%;
        listen       127.0.0.1:%%PORT_3%%;
        server_name  localhost;

        location / {
            add_header X-Port $server_port;
            return 204;
        }
    }
}

EOF

plan(skip_all => 'no 127.0.0.1 on host')
	if http_get('/') !~ /X-IP: 127.0.0.1/m;

$t->plan(2);

###############################################################################

my @ports = my ($port1, $port2, $port3) = (port(1), port(2), port(3));

is(many('/', 30), "$port1: 15, $port2: 15", 'ip_hash');
is(many('/u2', 30), "$port1: 10, $port2: 10, $port3: 10", 'ip_hash 3 peers');

###############################################################################

sub many {
	my ($uri, $count) = @_;
	my %ports;

	for my $i (1 .. $count) {
		my $req = "GET $uri HTTP/1.0" . CRLF
			. "X-Real-IP: 127.0.$i.2" . CRLF . CRLF;

		if (http($req) =~ /X-Port: (\d+)/) {
			$ports{$1} = 0 unless defined $ports{$1};
			$ports{$1}++;
		}
	}

	my @keys = map { my $p = $_; grep { $p == $_ } keys %ports } @ports;
	return join ', ', map { $_ . ": " . $ports{$_} } @keys;
}

###############################################################################
