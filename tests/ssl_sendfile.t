#!/usr/bin/perl

# (C) 2026 Web Server LLC
# (C) Maxim Dounin

# Tests for http ssl module, SSL_sendfile() usage.

###############################################################################

use warnings;
use strict;

use POSIX qw(uname);
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl openssl:3.0.0 socket_ssl/)
	->has_daemon('openssl')->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 sndbuf=16k;
        listen       127.0.0.1:8443 ssl sndbuf=16k;
        server_name  localhost;

        sendfile on;
        ssl_conf_command Options KTLS;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
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

$t->run();

$t->write_file('small', 'SEE-THIS');
$t->write_file('big', ('123456789' x 30000) . 'SEE-THIS');

###############################################################################

like(http_get('/small', SSL => 1), qr/SEE-THIS/, 'sendfile small');

TODO: {
	my @uname = uname();
	my ($major, $minor) = $uname[2] =~ /([0-9])\.([0-9]+)/;

	local $TODO = 'sending big buffers over ssl connection with kTLS using '
		. 'openssl 3.0 and kernel 5.14.x may stall tcp connection'
		if !$t->has_feature('openssl:3.0.8')
			or ($major == 5 && $minor >= 14)
			or ($major == 6 && $minor < 1);

	like(http_get('/big', SSL => 1, sleep => 0.5),
		qr/^(123456789){30000}SEE-THIS$/m, 'sendfile big');
}

like(http_get('/small'), qr/SEE-THIS/, 'sendfile plain small');
like(http_get('/big', sleep => 0.5),
	qr/^(123456789){30000}SEE-THIS$/m, 'sendfile plain big');

###############################################################################
