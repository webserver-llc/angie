#!/usr/bin/perl

# (C) 2025 Web Server LLC

# ACME hooks tests using NJS

# The hook_handler function is implemented using
# the r.subrequest method to control the challenge server.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/acme socket_ssl http_ssl njs/)
	->has_daemon('openssl');

# At the time of writing, NJS crashes on this test
# if built with clang using the -fsanitize=cfi option.
plan(skip_all => 'unsafe njs build')
	# counterintuitive usage of has_module
	# but this works
	if $t->has_module('-fsanitize=cfi');

my $has_alpn = !$t->has_module('BoringSSL|AWS-LC|LibreSSL');

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 20053;

my $acme_helper = Test::Nginx::ACME->new({
	t => $t,
	dns_port => $dns_port,
});

my $d = $t->testdir();

my $http_port = port(5002);
my $tls_port = port(5001);
my $pebble_port = port(14000);
my $challtestsrv_mgmt_port = port(9055);

my (@clients, @servers);

my @keys = (
	{ type => 'rsa', bits => 2048 },
	{ type => 'ecdsa', bits => 256 },
);

my @challenges = ('http', 'dns');

if ($has_alpn) {
	push @challenges, 'alpn';
}

my $server_count = @challenges * @keys;

my $domain_count = 1;

# Each iteration creates 2 clients, one with the RSA key type, the other with
# the ECDSA. Each subsequent iteration also assigns a different challenge type.
for (1 .. $server_count) {
	my $n = $_;

	my $chlg = $challenges[($n - 1) % @challenges];

	my $srv = {
		domains => [],
		clients => [],
	};

	for (1 .. 2) {
		push @{ $srv->{domains} }, "angie-test${domain_count}.com";
		$domain_count++;
	}

	if ($chlg eq 'dns') {
		# The dns-01 validation method allows wildcard domain names.
		push @{ $srv->{domains} }, "*.angie-test${domain_count}.com";
		$domain_count++;
	}

	for my $key (@keys) {
		my $cli = {
			name => "test${n}_$key->{type}_$chlg",
			key_type => $key->{type},
			key_bits => $key->{bits},
			challenge => $chlg,
			renewed => 0,
			enddate => "n/a",
		};

		push @clients, $cli;
		push @{ $srv->{clients} }, $cli;
	}

	push @servers, $srv;
}

my $conf_clients = '';
my $conf_servers = '';
my $conf_hooks = '';

my $account_key = '';
my $email = '';
my $uri = "uri=/?client=\$acme_hook_client"
	. "&hook=\$acme_hook_name"
	. "&challenge=\$acme_hook_challenge"
	. "&domain=\$acme_hook_domain"
	. "&token=\$acme_hook_token"
	. "&keyauth=\$acme_hook_keyauth"
;

for my $e (@clients) {
	$conf_clients .= "    acme_client $e->{name} "
		. "https://localhost:$pebble_port/dir challenge=$e->{challenge} "
		. "key_type=$e->{key_type} key_bits=$e->{key_bits} "
		. "$account_key $email;\n";

	$account_key = "account_key=$d/acme_client/$clients[0]->{name}/account.key";

	$conf_hooks .= "            acme_hook $e->{name} $uri;\n";

	# The even clients have an "email" parameter -- for a change...
	$email = ($email eq '' ) ? "email=admin\@angie-test.com" : '';

}

for my $e (@servers) {

	$conf_servers .=
"    server {
        listen       localhost:%%PORT_8080%%;
        server_name  @{ $e->{domains} };

";

	for my $cli (@{ $e->{clients} }) {
		$conf_servers .= "        acme $cli->{name};\n";
	}

	$conf_servers .= "    }\n\n";
}

my $conf =
"
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    variables_hash_max_size  2048;

    client {
        location \@acme_hook_handler {
            proxy_pass       http://127.0.0.1:$challtestsrv_mgmt_port/\$args;
        }

        location \@hook {
$conf_hooks
            js_content       acme.hook_handler;
        }
    }

    js_import acme.js;

    resolver localhost:$dns_port ipv6=off;

$conf_servers
$conf_clients
}
";

$t->write_file_expand('nginx.conf', $conf);

$t->write_file_expand('acme.js', <<"EOF");

import fs from 'fs';
import qs from 'querystring';

const sleep = (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function hook_handler(r) {
    r.log("entered hook_handler()");

    const client =    r.variables.acme_hook_client;
    const hook =      r.variables.acme_hook_name
    const challenge = r.variables.acme_hook_challenge;
    const domain =    r.variables.acme_hook_domain;
    const token =     r.variables.acme_hook_token;
    const keyauth =   r.variables.acme_hook_keyauth;

    r.log("client =    " + client);
    r.log("hook =      " + hook);
    r.log("challenge = " + challenge);
    r.log("domain =    " + domain);
    r.log("token =     " + token);
    r.log("keyauth =   " + keyauth);

//    await sleep(0);

    if (hook == 'add') {
        if (challenge == 'http') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'add-http01',
                            body: `{"token":"\${token}","content":"\${keyauth}"}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook added\\n'));

        } else if (challenge == 'dns') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'set-txt',
                            body: `{"host":"_acme-challenge.\${domain}.","value":"\${keyauth}"}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook added\\n'));

        } else if (challenge == 'alpn') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'add-tlsalpn01',
                            body: `{"host":"\${domain}","content":"\${keyauth}"}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook added\\n'));

        } else {
            r.return(400, 'Unknown challenge\\n');
        }

    } else if (hook == 'remove') {
        if (challenge == 'http') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'del-http01',
                            body: `{"token":"\${token}."}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook removed\\n'));

        } else if (challenge == 'dns') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'clear-txt',
                            body: `{"host":"_acme-challenge.\${domain}."}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook removed\\n'));

        } else if (challenge == 'alpn') {
            r.subrequest('\@acme_hook_handler',
                        {
                            args: 'del-tlsalpn01',
                            body: `{"host":"\${domain}"}`,
                            method: "POST"
                        })
                .then(reply => r.return(200, 'Hook removed\\n'));

        } else {
            r.return(400, 'Unknown challenge\\n');
        }

    } else {
        r.return(400, 'Unknown hook\\n');
    }

    const uri = r.variables.request_uri.slice(2); // skip '/?'
    const q = qs.parse(uri);
    const uri_status =
        client == q['client'] &&
        hook == q['hook'] &&
        challenge == q['challenge'] &&
        domain == q['domain'] &&
        token == q['token'] &&
        keyauth == q['keyauth'];

    fs.appendFileSync('$d/uri.txt', `URI: \${uri_status}\\n`);

    r.log("left hook_handler()");
}


export default {
    hook_handler
};

EOF

$acme_helper->start_challtestsrv({
	mgmt_port => $challtestsrv_mgmt_port,
	http_port => $http_port,
	tlsalpn_port => $tls_port,
});

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	http_port => $http_port,
	tls_port => $tls_port,
});

$t->run();

$t->plan(scalar @clients + 2);

my $renewed_count = 0;
my $loop_start = time();

for (1 .. 60 * @clients) {

	for my $cli (@clients) {
		next if $cli->{renewed};

		my $cert_file = "$d/acme_client/$cli->{name}/certificate.pem";

		if (-s $cert_file) {
			my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

			next if $s eq '';

			chomp $s;

			$renewed_count++;
			note("$0: $cli->{name} renewed certificate "
				. " ($renewed_count of " . @clients . ")");

			$cli->{renewed} = 1;
			$cli->{enddate} = $s;
		}
	}

	last if $renewed_count == @clients;

	if (!$renewed_count && time() - $loop_start > 60) {
		# If none of the clients has renewed during this time,
		# then there's probably no need to wait longer.
		diag("$0: Quitting on timeout ...");
		last;
	}

	select undef, undef, undef, 0.5;
}

for my $cli (@clients) {
	ok($cli->{renewed}, "$cli->{name} renewed certificate " .
		"(challenge: $cli->{challenge}; enddate: $cli->{enddate})");
}

$t->stop();

my $s = '';

$s = $t->read_file('uri.txt') if -f $t->testdir() . '/uri.txt';

my $used_uri = $s =~ /URI:/;
my $bad_uri = !$used_uri || ($s =~ /URI: false/);

ok($used_uri, 'used uri parameter');
ok(!$bad_uri, 'valid uri parameter');

###############################################################################

