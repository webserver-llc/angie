#!/usr/bin/perl

# (C) 2025 Web Server LLC

# ACME test for multiple diverse clients

# This test script verifies that the ACME module correctly retrieves
# certificates in configurations with multiple diverse ACME clients. These
# clients may use different certificate types, challenge types, and challenge
# handling methods.
#
# The script first tests clients that handle challenges without hook procedures
# by running pebble and challtestsrv with the appropriate parameters for each
# challenge type and waiting until the clients have received their
# certificates (steps 1 & 2). It then tests clients that use hook procedures,
# again launching pebble and challtestsrv with the necessary parameters,
# along with the hook handling process (step 3).
#
# In some cases, an ACME client may begin updating before the required servers
# are ready; if this happens, the client will encounter an error and
# automatically retry the update based on its configuration.
#
# The test is considered successful when all ACME clients obtain their
# certificates as expected.

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Socket qw/ CRLF /;
use Test::More;
use Test::Deep qw/ eq_deeply /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require FCGI; };
plan(skip_all => 'FCGI not installed') if $@;

my $t = Test::Nginx->new()->has(qw/acme socket_ssl/);

# XXX
my $dns_port = 11053;
my $angie_dns_port = 11153;

my $acme_helper = Test::Nginx::ACME->new({
	t => $t,
	dns_port => $dns_port,
});

my $d = $t->testdir();

my $hook_port = port(9000);
my $pebble_port = port(14000);
my $http_port = port(5003);
my $challtestsrv_mgmt_port = port(9055);

my (@clients, @servers);

my @keys = (
	{ type => 'rsa', bits => 2048 },
	{ type => 'ecdsa', bits => 256 },
);

my @challenges = ('http', 'dns');

my $server_count = @challenges * 2;

my $domain_count = 1;
my $http_chlg_count = 0;
my $dns_chlg_count = 0;
my $hook_chlg_count = 0;

for my $n (1 .. $server_count) {

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

		# ".example.com" is equivalent to "example.com *.example.com".
		push @{ $srv->{domains} }, ".angie-test${domain_count}.com";
		$domain_count++;
	}

	my $hook = int(($n - 1) / ($server_count / 2));

	for my $key (@keys) {
		my $cli = {
			name => "test${n}_$key->{type}_${chlg}_"
				. ($hook ? 'hook' : 'nohook'),
			key_type => $key->{type},
			key_bits => $key->{bits},
			challenge => $chlg,
			hook => $hook,
			renewed => 0,
			enddate => "n/a",
		};

		push @clients, $cli;
		push @{ $srv->{clients} }, $cli;

		$http_chlg_count += ($chlg eq 'http' and !$hook);
		$dns_chlg_count += ($chlg eq 'dns' and !$hook);
		$hook_chlg_count += $hook;
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
		. "https://127.0.0.1:$pebble_port/dir challenge=$e->{challenge} "
		. "key_type=$e->{key_type} key_bits=$e->{key_bits} "
		# Some clients may start updating their certificates before we set up
		# the corresponding servers, which will cause errors. To handle this,
		# we simply restart the update as soon as possible by setting
		# an appropriate value for the retry_after_error parameter.
		. "retry_after_error=2s "
		. "$account_key $email;\n";

	$account_key = "account_key=$d/acme_client/$clients[0]->{name}/account.key";

	$conf_hooks .= "            acme_hook $e->{name} $uri;\n" if $e->{hook};

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

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # Prevent the "could not build optimal variables_hash..." warning
    variables_hash_max_size 2048;

    # We don't need a resolver directive because we specify IPs
    # as ACME server addresses.
    #resolver localhost:$dns_port ipv6=off;

    acme_dns_port $angie_dns_port;
    acme_http_port $http_port;

$conf_clients
$conf_servers

    server {
        listen       localhost:%%PORT_8080%%;

        location / {
            internal;

$conf_hooks
            fastcgi_pass localhost:$hook_port;

            fastcgi_param ACME_CLIENT           \$acme_hook_client;
            fastcgi_param ACME_HOOK             \$acme_hook_name;
            fastcgi_param ACME_CHALLENGE        \$acme_hook_challenge;
            fastcgi_param ACME_DOMAIN           \$acme_hook_domain;
            fastcgi_param ACME_TOKEN            \$acme_hook_token;
            fastcgi_param ACME_KEYAUTH          \$acme_hook_keyauth;

            fastcgi_param REQUEST_URI           \$request_uri;
        }
    }
}
EOF

# Step 1

$acme_helper->start_challtestsrv({
	mgmt_port => $challtestsrv_mgmt_port
});

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	http_port => $http_port
});

$t->run();

$t->plan(scalar @clients + 2);

my $renewed_count = 0;
my $n = 0;
my $cli_timeout = 360;
my $loop_start = time();

for (1 .. $cli_timeout * $http_chlg_count) {

	for my $cli (@clients) {
		next if ($cli->{renewed}
			or $cli->{challenge} ne 'http'
			or $cli->{hook});

		my $cert_file = "$d/acme_client/$cli->{name}/certificate.pem";

		if (-s $cert_file) {
			my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

			next if $s eq '';

			chomp $s;

			$renewed_count++;
			$n++;

			note("$0: $cli->{name} renewed certificate "
				. " ($renewed_count of " . @clients . ")");

			$cli->{renewed} = 1;
			$cli->{enddate} = $s;
		}
	}

	last if $n == $http_chlg_count;

	if (!$n && time() - $loop_start > $cli_timeout) {
		# If none of the clients has renewed during this time,
		# then there's probably no need to wait longer.
		diag("$0: Quitting on timeout ...");
		goto bad;
	}

	select undef, undef, undef, 0.5;
}

$acme_helper->stop_pebble();
$acme_helper->stop_challtestsrv();

# Step 2

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	dns_port => $angie_dns_port,
});


$n = 0;
$cli_timeout = 360;
$loop_start = time();

for (1 .. $cli_timeout * $dns_chlg_count) {

	for my $cli (@clients) {
		next if ($cli->{renewed}
			or $cli->{challenge} ne 'dns'
			or $cli->{hook});

		my $cert_file = "$d/acme_client/$cli->{name}/certificate.pem";

		if (-s $cert_file) {
			my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

			next if $s eq '';

			chomp $s;

			$renewed_count++;
			$n++;

			note("$0: $cli->{name} renewed certificate "
				. " ($renewed_count of " . @clients . ")");

			$cli->{renewed} = 1;
			$cli->{enddate} = $s;
		}
	}

	last if $n == $dns_chlg_count;

	if (!$n && time() - $loop_start > $cli_timeout) {
		# If none of the clients has renewed during this time,
		# then there's probably no need to wait longer.
		diag("$0: Quitting on timeout ...");
		goto bad;
	}

	select undef, undef, undef, 0.5;
}

$acme_helper->stop_pebble();

# Step 3

$acme_helper->start_challtestsrv({
	mgmt_port => $challtestsrv_mgmt_port
});

$acme_helper->start_pebble({
	pebble_port => $pebble_port,
	http_port => $http_port
});

$t->run_daemon(\&hook_handler, $t, $hook_port);

$n = 0;
$cli_timeout = 360;
$loop_start = time();

for (1 .. $cli_timeout * $hook_chlg_count) {

	for my $cli (@clients) {
		next if ($cli->{renewed} or !$cli->{hook});

		my $cert_file = "$d/acme_client/$cli->{name}/certificate.pem";

		if (-s $cert_file) {
			my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

			next if $s eq '';

			chomp $s;

			$renewed_count++;
			$n++;

			note("$0: $cli->{name} renewed certificate "
				. " ($renewed_count of " . @clients . ")");

			$cli->{renewed} = 1;
			$cli->{enddate} = $s;
		}
	}

	last if $n == $hook_chlg_count;

	if (!$n && time() - $loop_start > $cli_timeout) {
		# If none of the clients has renewed during this time,
		# then there's probably no need to wait longer.
		diag("$0: Quitting on timeout ...");
		last;
	}

	select undef, undef, undef, 0.5;
}

bad:

for my $cli (@clients) {
	ok($cli->{renewed}, "$cli->{name} renewed certificate " .
		"(challenge: $cli->{challenge}; enddate: $cli->{enddate})");
}

$t->stop();

my $s = '';

$s = $t->read_file('uri.txt') if -f $t->testdir() . '/uri.txt';

my $used_uri = $s =~ /URI:/;
my $bad_uri = !$used_uri or ($s =~ /URI: 0/);

ok($used_uri, 'used uri parameter');
ok(!$bad_uri, 'valid uri parameter');

###############################################################################

sub hook_add {
	my ($challenge, $hook, $domain, $token, $keyauth) = @_;

	if ($challenge eq 'http') {
		http_post('/add-http01',
			body => "{\"token\":\"$token\",\"content\":\"$keyauth\"}");

	} elsif ($challenge eq 'dns') {
		my $name = "_acme-challenge.$domain.";

		http_post('/set-txt',
			body => "{\"host\":\"$name\",\"value\":\"$keyauth\"}");
	} else {
		die('Unknown challenge ' . $challenge);
	}
}

sub hook_remove {
	my ($challenge, $hook, $domain, $token, $keyauth) = @_;

	if ($challenge eq 'http') {
		http_post('/del-http01', body => "{\"token\":\"$token\"}");

	} elsif ($challenge eq 'dns') {
		my $name = "_acme-challenge.$domain.";

		http_post('/clear-txt', body => "{\"host\":\"$name\"}");

	} else {
		die('Unknown challenge ' . $challenge);
	}
}

sub check_uri {
	# This function parses $uri and checks whether its parameters
	# match those in %h.
	my ($uri, %h) = @_;

	# discard '/?'
	$uri = substr $uri, 2;

	my %h2;
	for my $s (split(/&/, $uri)) {
		my ($k, $v) = split(/=/, $s);
		$h2{$k} = $v;
	}

	return eq_deeply(\%h, \%h2);
}

sub hook_handler {
	my ($t, $hook_port) = @_;

	my $socket = FCGI::OpenSocket(":$hook_port", 5);
	my $req = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket);
	my $uri_status = -1;

	while ($req->Accept() >= 0) {
		my %h = (
			client => $ENV{ACME_CLIENT},
			hook => $ENV{ACME_HOOK},
			challenge => $ENV{ACME_CHALLENGE},
			domain => $ENV{ACME_DOMAIN},
			token => $ENV{ACME_TOKEN},
			keyauth => $ENV{ACME_KEYAUTH},
		);

		if ($h{hook} eq 'add') {
			hook_add($h{challenge}, $h{hook}, $h{domain}, $h{token}, $h{keyauth});

		} elsif ($h{hook} eq 'remove') {
			hook_remove($h{challenge}, $h{hook}, $h{domain}, $h{token}, $h{keyauth});

		} else {
			print "Status: 400\r\n";
		}

		print "\r\n";

		# Check whether REQUEST_URI contains all the data from the hook
		# variables and write this info to a file.
		my $uri = $ENV{REQUEST_URI};

		$uri_status = check_uri($uri, %h) if $uri_status != 0;

		open my $f, '>>', $t->testdir() . '/uri.txt'
			or die "Couldn't open uri.txt: $!";

		print $f "URI: $uri_status\n";

		close $f;
	}

	FCGI::CloseSocket($socket);
}

###############################################################################

sub http_post {
	my ($url, %extra) = @_;

	my $peer = "127.0.0.1:$challtestsrv_mgmt_port";

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => $peer,
	)
	or die "Can't connect to challtestsrv ($peer): $!\n";

	$extra{socket} = $s;

	my $p = "POST $url HTTP/1.0" . CRLF .
		"Host: localhost" . CRLF .
		"Content-Length: ". length($extra{body}) . CRLF .
		CRLF;

	return http($p, %extra);
}

