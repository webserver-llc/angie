package Test::Nginx::DoH;

# (C) 2026 Web Server LLC

# Helper module for DNS-over-HTTPS (DoH) tests.
# Provides I/O helpers, DNS message builders, HTTP helpers,
# and generic daemon loops for use in test files.

use warnings;
use strict;

use Exporter qw/import/;
use IO::Select;
use IO::Socket::INET;
use MIME::Base64 qw/encode_base64url/;

use Test::Nginx qw/http http_get/;

our @EXPORT_OK = qw/
	read_tcp_query send_tcp_response dns_query
	copy_question_section dns_response dns_nxdomain_response dns_tc_response
	dns_soa_nxdomain_response dns_nxdomain_auth_malformed_response
	dns_nxdomain_auth_trunc_response dns_nxdomain_auth_rdlen_overflow_response
	dns_soa_rdlen_oob_response POST_req doh_post doh_get doh_extract_body
	doh_query_id doh_tc_flag doh_ancount doh_rcode tcp_dns_daemon
	udp_dns_daemon dual_dns_daemon dns_blackhole_daemon
/;

our %EXPORT_TAGS = (
	io  => [qw/read_tcp_query send_tcp_response/],
	dns => [qw/
		dns_query copy_question_section dns_response dns_nxdomain_response
		dns_tc_response dns_soa_nxdomain_response
		dns_nxdomain_auth_malformed_response dns_nxdomain_auth_trunc_response
		dns_nxdomain_auth_rdlen_overflow_response dns_soa_rdlen_oob_response
	/],
	http => [qw/
		POST_req doh_post doh_get doh_extract_body doh_query_id doh_tc_flag
		doh_ancount doh_rcode
	/],
	daemon => [qw/
		tcp_dns_daemon udp_dns_daemon dual_dns_daemon dns_blackhole_daemon
	/],
);

###############################################################################
# I/O helpers
###############################################################################

sub read_tcp_query {
	my ($client) = @_;

	my $n = $client->read(my $len_buf, 2);
	return if !defined $n || $n < 2;

	my $len = unpack('n', $len_buf);
	my $query_data = '';
	while (length($query_data) < $len) {
		$n = $client->read(my $buf, $len - length($query_data));
		last if !defined $n || $n == 0;
		$query_data .= $buf;
	}

	return if length($query_data) < $len;
	return $query_data;
}

sub send_tcp_response {
	my ($client, $response_data) = @_;
	my $response_len = pack('n', length($response_data));
	$client->write($response_len . $response_data);
}

###############################################################################
# DNS helpers
###############################################################################

sub dns_query {
	my ($name, $type) = @_;

	my $id = int(rand(65536));
	my $flags = 0x0100;  # RD=1
	my $header = pack('nnnnnn', $id, $flags, 1, 0, 0, 0);

	my $qname = '';
	for my $label (split /\./, $name) {
		$qname .= pack('C', length($label)) . $label;
	}
	$qname .= pack('C', 0);  # root label

	my $question = $qname . pack('nn', $type, 1);  # TYPE=A, CLASS=IN

	return $header . $question;
}

sub copy_question_section {
	my ($query_data) = @_;

	my $qdcount = unpack('n', substr($query_data, 4, 2));
	my $offset = 12;
	my $question = '';

	for (my $i = 0; $i < $qdcount; $i++) {
		while ($offset < length($query_data)) {
			my $label_len = unpack('C', substr($query_data, $offset, 1));
			$offset++;
			last if $label_len == 0;
			$offset += $label_len;
		}
		$question .= substr($query_data, 12, $offset - 12 + 4);
		$offset += 4;
	}

	return ($question, $offset);
}

sub dns_response {
	my ($query_data, $addr, $ttl) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	my $resp_flags = 0x8180;  # QR=1, RD=1, RA=1, RCODE=NOERROR
	my $ancount = 1;

	my $header = pack('nnnnnn', $id, $resp_flags, $qdcount, $ancount, 0, 0);

	# Copy question section from query
	my ($question, $offset) = copy_question_section($query_data);

	# Build answer section: compression pointer + A record
	my $answer = pack('n', 0xc00c);          # name: compression ptr
	$answer .= pack('nnNn', 1, 1, $ttl, 4);  # TYPE=A, CLASS=IN, TTL, RDLENGTH
	$answer .= pack('CCCC', split(/\./, $addr)); # RDATA

	return $header . $question . $answer;
}

sub dns_nxdomain_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3
	my $resp_flags = 0x8183;
	my $header = pack('nnnnnn', $id, $resp_flags, $qdcount, 0, 0, 0);

	# Copy question section
	my ($question, $offset) = copy_question_section($query_data);

	# SOA in authority section (RFC 2308)
	my $soa_name = pack('C', 0);  # root label
	my $mname = pack('C', 7) . 'example' . pack('C', 3) . 'com' . pack('C', 0);
	my $rname = pack('C', 4) . 'host' . $mname;
	my $soa_rdata = $mname . $rname
		. pack('NNNNN', 1, 3600, 900, 604800, 86400);
	my $soa = $soa_name . pack('nnNn', 6, 1, 3600, length($soa_rdata))
		. $soa_rdata;

	# NSCOUNT=1
	substr($header, 8, 2) = pack('n', 1);

	return $header . $question . $soa;
}

sub dns_tc_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# Flags: QR=1, TC=1, RD=1, RA=1, RCODE=NOERROR
	my $resp_flags = 0x8380;  # TC bit set
	my $header = pack('nnnnnn', $id, $resp_flags, $qdcount, 0, 0, 0);

	# Copy question section from query
	my ($question, $offset) = copy_question_section($query_data);

	return $header . $question;
}

sub dns_soa_nxdomain_response {
	my ($query_data, $soa_ttl, $minimum) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3, NSCOUNT=1
	my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);

	my ($question, $offset) = copy_question_section($query_data);
	$response .= $question;

	# SOA with custom TTL and MINIMUM
	my $soa_name = pack('C', 0);
	my $mname = pack('C', 7) . 'example' . pack('C', 3) . 'com' . pack('C', 0);
	my $rname = pack('C', 4) . 'host' . $mname;
	my $soa_rdata = $mname . $rname
		. pack('NNNNN', 1, $soa_ttl, 900, 604800, $minimum);
	my $soa = $soa_name . pack('nnNn', 6, 1, $soa_ttl, length($soa_rdata))
		. $soa_rdata;

	$response .= $soa;

	return $response;
}

sub dns_nxdomain_auth_malformed_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3, NSCOUNT=1
	my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);

	my ($question, $offset) = copy_question_section($query_data);
	$response .= $question;

	# Malformed authority: label type 0x80 (invalid)
	$response .= pack('C', 0x80);
	$response .= pack('nnNn', 6, 1, 3600, 4);
	$response .= pack('CCCC', 0, 0, 0, 0);

	return $response;
}

sub dns_nxdomain_auth_trunc_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3, NSCOUNT=1
	my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);

	my ($question, $offset) = copy_question_section($query_data);
	$response .= $question;

	# Authority: valid root name, then only 4 bytes (need 10)
	$response .= pack('C', 0);  # root name
	$response .= pack('nn', 6, 1);  # TYPE=SOA, CLASS=IN (only 4 bytes)

	return $response;
}

sub dns_nxdomain_auth_rdlen_overflow_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3, NSCOUNT=1
	my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);

	my ($question, $offset) = copy_question_section($query_data);
	$response .= $question;

	# Authority: SOA with rdlength=200 but no RDATA
	$response .= pack('C', 0);  # root name
	$response .= pack('nnNn', 6, 1, 3600, 200);  # rdlength=200, no data

	return $response;
}

sub dns_soa_rdlen_oob_response {
	my ($query_data) = @_;

	my ($id, $flags, $qdcount) = unpack('nnn', $query_data);

	# NXDOMAIN: QR=1, RD=1, RA=1, RCODE=3, NSCOUNT=1
	my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);

	my ($question, $offset) = copy_question_section($query_data);
	$response .= $question;

	# Authority: SOA with rdlength claiming 30 bytes of RDATA,
	# but only 18 bytes actually present.  MNAME and RNAME are valid
	# root labels so skip_name succeeds; then the MINIMUM(4) read
	# lands past the buffer end — triggering an OOB read.
	$response .= pack('C', 0);  # root name (SOA owner)
	$response .= pack('nnNn', 6, 1, 3600, 30);  # TYPE=SOA, RDLENGTH=30
	$response .= pack('C', 0);  # MNAME = root
	$response .= pack('C', 0);  # RNAME = root
	# SERIAL+REFRESH+RETRY+EXPIRE
	$response .= pack('NNNN', 1, 3600, 900, 604800);
	# MINIMUM(4) is missing — RDLENGTH claims it exists but buffer ends here

	return $response;
}

###############################################################################
# HTTP helpers
###############################################################################

sub POST_req {
	my ($url, $body, %extra) = @_;

	my $content_type = delete $extra{'Content-Type'} // '';
	my $content_length = length($body);

	my $ct_header = ($content_type) ? "Content-Type: $content_type\r\n" : '';

	return "POST $url HTTP/1.0\r\nHost: localhost\r\n"
		. "${ct_header}Content-Length: $content_length\r\n\r\n$body";
}

sub doh_post {
	my ($url, $query) = @_;
	return http(POST_req($url, $query,
		'Content-Type' => 'application/dns-message'));
}

sub doh_get {
	my ($url, $query) = @_;
	my $encoded = encode_base64url($query);
	return http_get("$url?dns=$encoded");
}

sub doh_extract_body {
	my ($resp) = @_;
	my ($body) = $resp =~ /\r\n\r\n(.+)/s;
	return $body;
}

sub doh_query_id {
	my ($body) = @_;
	return defined $body && length($body) >= 2
		? unpack('n', substr($body, 0, 2))
		: 0;
}

sub doh_tc_flag {
	my ($body) = @_;
	return defined $body && length($body) >= 3
		? (ord(substr($body, 2, 1)) & 0x02) >> 1
		: 1;
}

sub doh_ancount {
	my ($body) = @_;
	return defined $body && length($body) >= 8
		? unpack('n', substr($body, 6, 2))
		: 0;
}

sub doh_rcode {
	my ($body) = @_;
	return defined $body && length($body) >= 4
		? ord(substr($body, 3, 1)) & 0x0f
		: 0xff;
}

###############################################################################
# Daemon loops
###############################################################################

sub tcp_dns_daemon {
	my ($t, $port, $builder, %opts) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS TCP server socket on port $port: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my $persistent = $opts{persistent} // 0;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		if ($persistent) {
			# Handle multiple requests on the same connection (keepalive)
			while (1) {
				my $query_data = read_tcp_query($client);
				last if !defined $query_data;

				my $response_data = $builder->($query_data);
				next if !defined $response_data;

				send_tcp_response($client, $response_data);
			}
		} else {
			my $query_data = read_tcp_query($client);
			if (defined $query_data) {
				my $response_data = $builder->($query_data);
				if (defined $response_data) {
					send_tcp_response($client, $response_data);
				}
			}
		}

		$client->close;
	}
}

sub udp_dns_daemon {
	my ($t, $port, $builder) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'udp',
		Reuse     => 1,
	) or die "Can't create DNS UDP server socket on port $port: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (1) {
		my $client_addr = $server->recv(my $query_data, 65535);
		last unless defined $client_addr;
		next if length($query_data) < 12;

		my $response_data = $builder->($query_data);
		next if !defined $response_data;

		$server->send($response_data, 0, $client_addr);
	}
}

sub dual_dns_daemon {
	my ($t, $tcp_server, $udp_server, $tcp_builder, $udp_builder, %opts) = @_;

	local $SIG{PIPE} = 'IGNORE';

	my $sel = IO::Select->new($tcp_server, $udp_server);

	my $persistent = $opts{persistent} // 0;

	while (1) {
		my @ready = $sel->can_read(5);
		for my $sock (@ready) {
			if ($sock == $udp_server) {
				my $client_addr = $udp_server->recv(my $query_data, 65535);
				next unless defined $client_addr;
				next if length($query_data) < 12;

				my $response = $udp_builder->($query_data);
				next if !defined $response;

				$udp_server->send($response, 0, $client_addr);

			} elsif ($sock == $tcp_server) {
				my $client = $tcp_server->accept();
				next unless $client;
				$client->autoflush(1);

				if ($persistent) {
					while (1) {
						my $query_data = read_tcp_query($client);
						last if !defined $query_data;

						my $response_data =
							$tcp_builder->($query_data, $client);
						last if !defined $response_data;

						send_tcp_response($client, $response_data);
					}
				} else {
					my $query_data = read_tcp_query($client);
					if (defined $query_data) {
						my $response_data = $tcp_builder->($query_data);
						if (defined $response_data) {
							send_tcp_response($client, $response_data);
						}
					}
				}

				$client->close;
			}
		}
	}
}

sub dns_blackhole_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS blackhole server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $query_data = read_tcp_query($client);
		sleep(30);

		$client->close;
	}
}

1;
