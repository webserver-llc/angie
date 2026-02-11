#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME DNS-01 challenge tests

# "acme_dns_ttl" directive check
#
# The "acme_dns_ttl" directive specifies the TTL value used in DNS responses
# sent by the ACME client during DNS-01 challenges. To verify its correct
# behaviour, we set up a DNS relay that receives DNS messages from the ACME
# server and forwards them to the ACME client, and vice versa. When a DNS
# message is received from the ACME client, the TTL value is extracted and
# compared with the value specified by the "acme_dns_ttl" directive. The test
# passes if the values match.

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
my $angie_dns_port = 12053;
my $relay_dns_port = port(12054, udp => 1);
my $dns_ttl = 600;

my $acme_helper = Test::Nginx::ACME->new({
	t => $t, dns_port => $relay_dns_port
});

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
    #resolver localhost:$angie_dns_port ipv6=off;

    acme_dns_port $angie_dns_port;
    acme_dns_ttl  $dns_ttl;

$conf_servers
$conf_clients
}
EOF

$t->run_daemon(\&dns_relay, $angie_dns_port, $relay_dns_port, $dns_ttl, $t);
$t->waitforfile("$d/$angie_dns_port");

$acme_helper->start_pebble({pebble_port => $pebble_port});

$t->run()->plan(scalar @clients + 1);

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

my $ttl_ok = -e "$d/ttl_match" && ! -e "$d/ttl_mismatch";

ok($ttl_ok, 'acme_dns_ttl');

###############################################################################

sub dns_relay {
	my ($angie_dns_port, $relay_dns_port, $expected_ttl, $t) = @_;

	my $angie_socket = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $angie_dns_port,
		Proto    => 'udp',
	)
		or die "Can't create angie_socket: $!\n";

	my $pebble_socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $relay_dns_port,
		Proto     => 'udp',
		ReusePort => 1,
	)
		or die "Can't create pebble_socket: $!\n";

	my $sel = IO::Select->new($angie_socket, $pebble_socket);

	local $SIG{PIPE} = 'IGNORE';

	# signal we are ready
	open my $fh, '>', $t->testdir() . '/' . $angie_dns_port;
	close $fh;

	my @pebble_addrs;
	my $recv_data;

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {

			# $peer_addr is a binary representation of the sender's address
			my $peer_addr = $fh->recv($recv_data, 65536);

			if ($pebble_socket == $fh) {
				push @pebble_addrs, $peer_addr;

				$angie_socket->send($recv_data)
					or note("$0: error sending dns query to Angie: $!\n");

			} else {
				my $addr = shift @pebble_addrs;

				if (defined $addr) {
					$pebble_socket->send($recv_data, 0, $addr)
						or note("$0: error sending dns query to pebble: $!");

				} else {
					note("$0: unmatched dns query");
				}

				my $fname;
				my $ttl = extract_ttl($recv_data);

				if ($ttl == $expected_ttl) {
					$fname = $t->testdir() . '/ttl_match';

				} elsif ($ttl >= 0) {
					$fname = $t->testdir() . '/ttl_mismatch';

				} else {
					note("$0: couldn't extract ttl");
				}

				if (defined $fname && !-e $fname) {
					open my $fh, '>', $fname;
					close $fh;
				}
			}
		}
	}
}

###############################################################################

# recv_data is a raw binary DNS packet
sub extract_ttl {
	my ($recv_data) = @_;

	use constant TXT => 16;
	use constant IN  => 1;

	# 1. Start after the 12-byte header
	my $offset = 12;

	# 2. Walk through the QNAME
	while ($offset < length $recv_data) {
		my $length_byte = unpack("\@$offset C", $recv_data);

		if ($length_byte == 0) {
			# End of QNAME reached
			$offset++;
			last;
		}

		# Check for DNS pointers (0xc0) in Question section
		# (Rare in Questions, but standard for safety)
		if (($length_byte & 0xc0) == 0xc0) {
			$offset += 2;
			last;
		}

		# Move offset: length byte + the label characters
		$offset += 1 + $length_byte;
	}

	# 3. Extract QTYPE (2 bytes) and QCLASS (2 bytes)
	my ($type, $class) = unpack("x$offset n2", $recv_data);
	if ($type != TXT || $class != IN) {
		return -1;
	}
	$offset += 4;

	# 4. $offset is currently at the start of the Answer Section
	while ($offset < length $recv_data) {
		# Skip the Name Field
		# We don't care what the name is, we just need to find where it ends
		my $byte = unpack("\@$offset C", $recv_data);

		# It's a pointer (0xc0XX), which is always 2 bytes
		if (($byte & 0xc0) == 0xc0) {
			$offset += 2;
			last;
		} elsif ($byte == 0x00) {
			# It's the null terminator for a label sequence
			$offset++;
			last;
		} else {
			# It's a length byte for a label (e.g., '6' for 'google')
			# Skip the length byte + the label itself
			$offset += 1 + $byte;
		}
	}

	# Extract TTL
	# Now offset is at Type(2) + Class(2) + TTL(4)
	# We skip the 4 bytes of Type/Class to hit the TT
	($type, $class, my $ttl) = unpack("\@$offset n2 N", $recv_data);

	if ($type != TXT || $class != IN) {
		return -1;
	}

	return $ttl;
}
