#!/usr/bin/perl

# (C) 2026 Web Server LLC

# ACME DNS-01 challenge test

# The test verifies that ACME DNS-01 challenge requests and responses are
# correctly routed through the expected network interfaces.
#
# A DNS relay daemon is set up to sit between pebble and Angie. The relay
# listens for DNS queries from pebble on one address (127.0.0.1) and forwards
# them to Angie on a different one (127.0.0.2). This means Angie receives the
# queries on 127.0.0.2 and must send its responses back to that same interface
# -- not to 127.0.0.1 or any other address the kernel might pick on its own.
#
# The test then launches an ACME client configured to use the DNS-01 challenge
# and waits for certificate renewal to complete successfully. A successful
# renewal confirms that the DNS challenge responses made it back to pebble
# through the relay, which in turn confirms that Angie sent each response out
# on the correct interface -- the one the request arrived on.

# This script requires pebble (see Test::Nginx::ACME for details).

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket;

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
my $angie_dns_port = 12553;
my $relay_dns_port = port(12554, udp => 1);

my $verbose = $ENV{TEST_ANGIE_VERBOSE} // 0;

my $acme_helper = Test::Nginx::ACME->new({
	t => $t, dns_port => $relay_dns_port
});

my $d = $t->testdir();

my $pebble_port = port(14000);

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

    server {
        listen       localhost:%%PORT_8080%%;

        # a wildcard domain is required
        server_name  *.angie-test.com;

        acme test;
    }

    acme_client test https://127.0.0.1:$pebble_port/dir challenge=dns;
}
EOF

$t->run_daemon(\&dns_relay, $angie_dns_port, $relay_dns_port, $t);
$t->waitforfile("$d/$angie_dns_port");

$acme_helper->start_pebble({pebble_port => $pebble_port});

$t->run()->plan(1);

my $cert_file = "$d/acme_client/test/certificate.pem";
my $renewed = 0;
my $enddate = 'n/a';

my $loop_start = time();

for (1 .. 60) {

	if (-s $cert_file) {
		my $s = `openssl x509 -in $cert_file -enddate -noout|cut -d= -f 2`;

		if ($s ne '') {
			chomp $s;

			$renewed = 1;
			$enddate = $s;

			last;
		}
	}

	select undef, undef, undef, 0.5;
}

ok($renewed, "renewed (enddate: $enddate)");

###############################################################################

sub dns_relay {
	my ($angie_dns_port, $relay_dns_port, $t) = @_;

	my $angie_socket = IO::Socket::INET->new(
		PeerAddr => '127.0.0.2',
		PeerPort => $angie_dns_port,
		Proto	 => 'udp',
	)
		or die "Can't create angie_socket: $!\n";

	my $pebble_socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $relay_dns_port,
		Proto	  => 'udp',
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

			if ($verbose) {
				my $from = addr_to_str($peer_addr);
				my $to = addr_to_str($fh->sockname());
				my $sz = length($recv_data);
				my $log_str = "$to <-- $sz <-- $from";
				$log_str .= (addr_port($peer_addr) == $angie_dns_port
							? ' (from Angie)' : ' (from pebble)');

				log_in($log_str);
			}

			if ($pebble_socket == $fh) {
				push @pebble_addrs, $peer_addr;

				if ($verbose) {
					my $from = addr_to_str($angie_socket->sockname());
					my $to = addr_to_str($angie_socket->peername());
					my $sz = length($recv_data);
					my $log_str = "$from --> $sz --> $to";

					log_out($log_str . ' (to Angie)');
				}

				$angie_socket->send($recv_data)
					or note("$0: error sending dns query to Angie: $!\n");

			} else {
				my $addr = shift @pebble_addrs;

				if (defined $addr) {

					if ($verbose) {
						my $from = addr_to_str($pebble_socket->sockname());
						my $to = addr_to_str($addr);
						my $sz = length($recv_data);
						my $log_str = "$from --> $sz --> $to";

						log_out($log_str . ' (to pebble)');
					}

					$pebble_socket->send($recv_data, 0, $addr)
						or note("$0: error sending dns query to pebble: $!");

				} else {
					note("$0: unmatched dns query");
				}
			}
		}
	}
}

sub addr_to_str {
	my ($addr) = @_;

	return "unknown" unless defined $addr;

	my ($port, $ip) = sockaddr_in($addr);
	$ip = inet_ntoa($ip);

	return "$ip:$port";
}

sub addr_port {
	my ($addr) = @_;

	return 0 unless defined $addr;

	my ($port, $ip) = sockaddr_in($addr);

	return $port;
}
