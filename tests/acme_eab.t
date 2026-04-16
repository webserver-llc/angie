#!/usr/bin/perl

# (C) 2026 Web Server LLC

# ACME External Account Binding test
#
# This test verifies that the "acme_client" directive correctly supports
# External Account Binding via a new parameter "eab" using all three supported
# HMAC algorithms: "HS256" (default), "HS384", and "HS512".
#
# Three ACME clients (test1, test2, test3) are configured, each with a distinct
# EAB key ID, secret key, and signing algorithm. A local pebble ACME server is
# started with matching EAB credentials. For each client, the test confirms
# that:
#
# 1. A certificate was successfully obtained from the ACME server (meaning EAB
#    authentication passed).
#
# 2. The certificate is actively served -- i.e., an SSL request to the
#    corresponding virtual host returns the expected response.
#
# The test passes only if all three clients both obtain and successfully use
# their certificates.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use List::Util qw/ sum0 /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme http_ssl socket_ssl/);

# XXX
my $dns_port = 22053;

my $acme_helper = Test::Nginx::ACME->new({
	t => $t, dns_port => $dns_port
});

my $d = $t->testdir();

my $pebble_port = port(14000);
my $http_port = port(5002);

my $n_clients = 3;

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # We don't need a resolver directive because we specify IPs
    # as ACME server addresses.
    #resolver localhost:$dns_port ipv6=off;

    acme_http_port $http_port;

    acme_client test1 https://127.0.0.1:$pebble_port/dir
        eab=test256:qzGsAtkfAzzHTPfjf6Sf0-yMyJjw88DN8Bn8hKxQ3yg
    ;

    acme_client test2 https://127.0.0.1:$pebble_port/dir
        eab=test384:HS384:H8If34UCAkZVI4Cp-eaheiFo-3xlCM49GoNtk89qHBWxOIq7skJdPtXO-xlgHABm
    ;

    acme_client test3 https://127.0.0.1:$pebble_port/dir
        eab=test512:HS512:YJWPDrDtzPoM_5gyyJzXT6SttQghtZ_zev_wcDbc1N66t_Z7n1mU785WfpfqcnhUCaKZYfQWolvR_tFROBuKdw
    ;

    server {
        listen       127.0.0.1:%%PORT_8443%% ssl;

        server_name  angie-test1.com;

        ssl_certificate      \$acme_cert_test1;
        ssl_certificate_key  \$acme_cert_key_test1;

        acme test1;

        location / {
            return           200 "SECURED 1";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8443%% ssl;

        server_name  angie-test2.com;

        ssl_certificate      \$acme_cert_test2;
        ssl_certificate_key  \$acme_cert_key_test2;

        acme test2;

        location / {
            return           200 "SECURED 2";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8443%% ssl;

        server_name  angie-test3.com;

        ssl_certificate      \$acme_cert_test3;
        ssl_certificate_key  \$acme_cert_key_test3;

        acme test3;

        location / {
            return           200 "SECURED 3";
        }
    }
}

EOF

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	http_port => $http_port,
	eab => {
		"test256" => "qzGsAtkfAzzHTPfjf6Sf0-yMyJjw88DN8Bn8hKxQ3yg",
		"test384" => "H8If34UCAkZVI4Cp-eaheiFo-3xlCM49GoNtk89qHBWxOIq7skJdPtXO-xlgHABm",
		"test512" => "YJWPDrDtzPoM_5gyyJzXT6SttQghtZ_zev_wcDbc1N66t_Z7n1mU785WfpfqcnhUCaKZYfQWolvR_tFROBuKdw",
	},
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(2 * $n_clients);

my @obtained = (0) x $n_clients;
my @used = (0) x $n_clients;

my $loop_start = time();

for (1 .. 40 * $n_clients) {

	for (0..$n_clients - 1) {
		if (!$obtained[$_]) {
			my $cert_file = "$d/acme_client/test@{[$_ + 1]}/certificate.pem";

			if (-s $cert_file) {
				$obtained[$_] = 1;

			} else {
				next;
			}
		}

		if (!$used[$_]) {
			my $domain = "angie-test@{[$_ + 1]}.com";

			my %extra = (
				SSL => 1,
				PeerAddr => '127.0.0.1:' . port(8443),
				SSL_hostname => $domain,
			);

			my $s = http(<<EOF, %extra);
POST / HTTP/1.0
Host: $domain

EOF

			$s = http_content($s) // '';
			if ($s eq "SECURED @{[$_ + 1]}") {
				$used[$_] = 1;
			}
		}
	}

	if (sum0(@obtained) == 0 && time() - $loop_start > 30) {
		# If none of the clients has obtained a certificate during this time,
		# then there's probably no need to wait longer.
		diag("$0: Quitting on timeout ...");
		last;
	}

	last if sum0(@obtained) == $n_clients && sum0(@used) == $n_clients;

	select undef, undef, undef, 0.5;
}

for (0..$n_clients - 1) {
	my $n = $_ + 1;

	ok($obtained[$_], "obtained certificate $n");
	ok($used[$_], "used certificate $n");
}

