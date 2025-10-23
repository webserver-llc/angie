#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME DNS-01 challenge tests

# This script requires pebble
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

my $t = Test::Nginx->new()->has(qw/acme http_ssl socket_ssl/)
	->has_daemon('openssl');

# XXX
my $dns_port = 12053;

my $acme_helper = Test::Nginx::ACME->new({t => $t, dns_port => $dns_port});

my $d = $t->testdir();

my $pebble_port = port(14000);

my (@clients, @servers);

my @keys = (
	{ type => 'rsa', bits => 2048 },
	{ type => 'ecdsa', bits => 256 },
);

my $domain_count = 1;

# Each iteration creates 2 clients, one with the RSA key type, the other with
# the ECDSA. Each subsequent iteration also assigns a different challenge type.
for (1 .. 2) {
	my $n = $_;

	my $srv = {
		domains => [],
		clients => [],
	};

	for (1 .. 2) {
		push @{ $srv->{domains} }, "angie-test${domain_count}.com";
		$domain_count++;
	}

	# The dns-01 validation method allows wildcard domain names.
	push @{ $srv->{domains} }, "*.angie-test${domain_count}.com";
	$domain_count++;

	# ".example.com" is equivalent to "example.com *.example.com".
	push @{ $srv->{domains} }, ".angie-test${domain_count}.com";
	$domain_count++;

	for my $key (@keys) {
		my $cli = {
			name => "test${n}_$key->{type}",
			key_type => $key->{type},
			key_bits => $key->{bits},
			challenge => 'dns',
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

my $account_key = '';
my $email = '';

for my $e (@clients) {
	$conf_clients .=  "    acme_client $e->{name} "
		. "https://127.0.0.1:$pebble_port/dir challenge=$e->{challenge} "
		. "key_type=$e->{key_type} key_bits=$e->{key_bits} "
		. "$account_key $email;\n";

	# for a change...
	$email = ($email eq '' ) ? "email=admin\@angie-test.com" : '';
	$account_key = "account_key=$d/acme_client/$clients[0]->{name}/account.key";
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

    acme_dns_port $dns_port;

$conf_servers
$conf_clients
}
EOF

$acme_helper->start_pebble({pebble_port => $pebble_port});

$t->run()->plan(scalar @clients);

my $renewed_count = 0;
my $loop_start = time();

for (1 .. 360 * @clients) {

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

	if (!$renewed_count && time() - $loop_start > 360) {
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

