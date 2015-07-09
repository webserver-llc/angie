#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for the proxy_limit_rate directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8080/data;
            proxy_limit_rate 12000;
            add_header X-Msec $msec;
        }

        location /data {
        }
    }
}

EOF

$t->write_file('data', 'X' x 40000);
$t->run();

###############################################################################

my $s = http_get('/', start => 1);
my $r = http_end_gentle($s);

my ($t1) = $r =~ /X-Msec: (\d+)/;
my $diff = time() - $t1;

# four chunks are split with three 1s delays + 1s error

cmp_ok(abs($diff - 3), '<=', 1, 'proxy_limit_rate');
like($r, qr/^(XXXXXXXXXX){4000}\x0d?\x0a?$/m, 'response body');

###############################################################################

sub http_end_gentle {
	my ($s) = @_;
	my $reply;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		local $/;
		$reply = $s->getline();

		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in("died: $@");
		return undef;
	}

	log_in($reply);
	return $reply;
}

###############################################################################
