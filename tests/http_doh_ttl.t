#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for the doh (DNS-over-HTTPS) module — Cache-Control, extract_min_ttl,
# and streaming.

###############################################################################

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ http :DEFAULT /;
use Test::Nginx::DoH qw(
	dns_query dns_response dns_nxdomain_response
	copy_question_section dns_soa_nxdomain_response
	dns_nxdomain_auth_malformed_response
	dns_nxdomain_auth_trunc_response dns_nxdomain_auth_rdlen_overflow_response
	dns_soa_rdlen_oob_response
	:io :daemon :http
);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http doh/)->plan(24);

my $cfg = <<'ENDCFG';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /dns-query {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
        }

        location /dns-query-nxdomain {
            doh_pass 127.0.0.1:8082;
            doh_transport tcp;
        }

        location /dns-query-no-answer {
            doh_pass 127.0.0.1:8083;
            doh_transport tcp;
        }

        location /dns-query-malformed {
            doh_pass 127.0.0.1:8084;
            doh_transport tcp;
        }

        location /dns-query-trunc-qtype {
            doh_pass 127.0.0.1:8085;
            doh_transport tcp;
        }

        location /dns-query-trunc-answer {
            doh_pass 127.0.0.1:8086;
            doh_transport tcp;
        }

        location /dns-query-fake-ancount {
            doh_pass 127.0.0.1:8087;
            doh_transport tcp;
        }

        location /dns-query-label-0x80 {
            doh_pass 127.0.0.1:8088;
            doh_transport tcp;
        }

        location /dns-query-multi-ttl {
            doh_pass 127.0.0.1:8089;
            doh_transport tcp;
        }

        location /dns-query-rdlength0 {
            doh_pass 127.0.0.1:8090;
            doh_transport tcp;
        }

        location /dns-query-uncompressed {
            doh_pass 127.0.0.1:8091;
            doh_transport tcp;
        }

        location /dns-query-udp {
            doh_pass 127.0.0.1:%%PORT_9081_UDP%%;
            doh_transport udp;
        }

        location /dns-query-stream-answer-fits {
            doh_pass 127.0.0.1:8092;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-stream-answer-no-fit {
            doh_pass 127.0.0.1:8093;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-stream-many-rrs {
            doh_pass 127.0.0.1:8094;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-stream-boundary-exact {
            doh_pass 127.0.0.1:8095;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-stream-boundary-not-streaming {
            doh_pass 127.0.0.1:8096;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-soa-minimum {
            doh_pass 127.0.0.1:8097;
            doh_transport tcp;
        }

        location /dns-query-auth-malformed {
            doh_pass 127.0.0.1:8098;
            doh_transport tcp;
        }

        location /dns-query-auth-trunc {
            doh_pass 127.0.0.1:8099;
            doh_transport tcp;
        }

        location /dns-query-auth-rdlen-overflow {
            doh_pass 127.0.0.1:8100;
            doh_transport tcp;
        }

        location /dns-query-filter-overflow {
            doh_pass 127.0.0.1:8101;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-label-overflow {
            doh_pass 127.0.0.1:8102;
            doh_transport tcp;
        }

        location /dns-query-no-root-label {
            doh_pass 127.0.0.1:8103;
            doh_transport tcp;
        }

        location /dns-query-question-overflow {
            doh_pass 127.0.0.1:8104;
            doh_transport tcp;
        }

        location /dns-query-max-size-large {
            doh_pass 127.0.0.1:8081;
            doh_transport tcp;
            doh_max_size 32768;
        }

        location /dns-query-soa-rdlen-oob {
            doh_pass 127.0.0.1:8105;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-ttl-overflow {
            doh_pass 127.0.0.1:8106;
            doh_transport tcp;
        }

        location /dns-query-soa-minimum-overflow {
            doh_pass 127.0.0.1:8107;
            doh_transport tcp;
        }

        location /dns-query-soa-mname-only {
            doh_pass 127.0.0.1:8108;
            doh_transport tcp;
        }

        location /dns-query-stream-boundary-1byte-over {
            doh_pass 127.0.0.1:8109;
            doh_transport tcp;
            doh_buffer_size 512;
        }

        location /dns-query-stream-boundary-ttl-fit-rdata-cut {
            doh_pass 127.0.0.1:8110;
            doh_transport tcp;
            doh_buffer_size 512;
        }
    }
}

ENDCFG

$t->write_file_expand('nginx.conf', $cfg);

# Normal TCP — TTL=300
$t->run_daemon(\&tcp_dns_daemon, $t, port(8081),
	sub { dns_response($_[0], '127.0.0.1', 300) });

# NXDOMAIN — SOA authority
$t->run_daemon(\&tcp_dns_daemon, $t, port(8082),
	sub { dns_nxdomain_response($_[0]) });

# No answer (ancount=0)
$t->run_daemon(\&tcp_dns_daemon, $t, port(8083),
	sub {
		my ($query_data) = @_;
		my ($question, $offset) = copy_question_section($query_data);
		my $qid = substr($query_data, 0, 2);
		my $qdcount = unpack('n', substr($query_data, 4, 2));
		return $qid . pack('nnnnnn', 0x8183, $qdcount, 0, 0, 0, 0)
			. $question;
	}
);

# Malformed — cycles truncated-question / truncated-answer
my $malformed_idx = 0;
$t->run_daemon(\&tcp_dns_daemon, $t, port(8084),
	sub {
		my ($query_data) = @_;
		my $idx = $malformed_idx++ % 2;
		my $qid = substr($query_data, 0, 2);
		if ($idx == 0) {
			return $qid . pack('nnnnn', 0x8180, 1, 1, 0, 0)
				. pack('C', 255) . "ab";
		} else {
			return $qid . pack('nnnnn', 0x8180, 1, 1, 0, 0)
				. "\x07example\x03com\x00"
				. pack('nn', 1, 1)
				. pack('n', 0xC00C)
				. pack('nn', 1, 1)
				. pack('N', 300)
				. pack('n', 4)
				. "\x7f";
		}
	}
);

# Truncated QTYPE+QCLASS
$t->run_daemon(\&tcp_dns_daemon, $t, port(8085),
	sub {
		my ($query_data) = @_;
		my $qid = length($query_data) >= 2
			? substr($query_data, 0, 2)
			: "\x00\x00";
		return $qid . pack('nnnnn', 0x8180, 1, 1, 0, 0)
			. "\x03foo\x00\x00\x01";
	}
);

# Truncated answer section
$t->run_daemon(\&tcp_dns_daemon, $t, port(8086),
	sub {
		my ($query_data) = @_;
		my $qid = length($query_data) >= 2
			? substr($query_data, 0, 2)
			: "\x00\x00";
		return $qid . pack('nnnnn', 0x8180, 1, 1, 0, 0)
			. "\x03foo\x00\x00\x01\x00\x01"
			. "\xc0\x0c\x00\x01\x00\x01";
	}
);

# Fake ancount
$t->run_daemon(\&tcp_dns_daemon, $t, port(8087),
	sub {
		my ($query_data) = @_;
		my $qid = length($query_data) >= 2
			? substr($query_data, 0, 2)
			: "\x00\x00";
		return $qid . pack('nnnnn', 0x8180, 1, 1, 0, 0)
			. "\x03foo\x00\x00\x01\x00\x01";
	}
);

# Label 0x80
$t->run_daemon(\&tcp_dns_daemon, $t, port(8088),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 1, 0, 0);
		$response .= $question;
		$response .= "\x80\x01\x02";
		$response .= pack('nnNn', 1, 1, 300, 4);
		$response .= pack('CCCC', 127, 0, 0, 1);
		return $response;
	}
);

# Multi-TTL
$t->run_daemon(\&tcp_dns_daemon, $t, port(8089),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 2, 0, 0);
		$response .= $question;
		$response .= pack('n', 0xc00c) . pack('nnNn', 1, 1, 300, 4)
			. pack('CCCC', 10, 0, 0, 1);
		$response .= pack('n', 0xc00c) . pack('nnNn', 1, 1, 60, 4)
			. pack('CCCC', 10, 0, 0, 2);
		return $response;
	}
);

# RDLENGTH=0, TTL=42
$t->run_daemon(\&tcp_dns_daemon, $t, port(8090),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 1, 0, 0);
		$response .= $question;
		$response .= pack('n', 0xc00c) . pack('nnNn', 40, 1, 42, 0);
		return $response;
	}
);

# Uncompressed names — TTL=60
$t->run_daemon(\&tcp_dns_daemon, $t, port(8091),
	sub {
		my ($query_data) = @_;
		my ($id, $flags) = unpack('nn', $query_data);
		my $response = pack('nnnnnn', $id, 0x8180, 1, 1, 0, 0);
		$response .= substr($query_data, 12);
		$response .= "\x07example\x03com\x00";
		$response .= pack('nn', 1, 1);
		$response .= pack('N', 60);
		$response .= pack('n', 4);
		$response .= pack('CCCC', 127, 0, 0, 1);
		return $response;
	}
);

# UDP — TTL=300
$t->run_daemon(\&udp_dns_daemon, $t, port(9081, udp => 1),
	sub { dns_response($_[0], '127.0.0.1', 300) });

# Stream answer-fits — 1 answer RR (TTL=300) + 1 additional RR (RDATA=460)
# Total: 12 + 17 + 16 + 472 = 517 DNS, 519 TCP.  At buffer 512: streaming
# triggered, but the answer RR (16 bytes at offset 29) fits in 510 DNS bytes.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8092),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 1, 0, 1);
		$response .= $question;
		$response .= pack('n', 0xc00c) . pack('nnNn', 1, 1, 300, 4)
			. pack('CCCC', 10, 0, 0, 1);
		$response .= pack('n', 0xc00c) . pack('nnNn', 41, 1, 60, 460)
			. ("\x00" x 460);
		return $response;
	}
);

# Stream answer-no-fit — 35 answer RRs (16 bytes each)
# Total: 12 + 17 + 35*16 = 589 DNS, 591 TCP.  At buffer 512: only 30 RRs
# fit in 510 DNS bytes (480), 31st is incomplete → no-store.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8093),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $ancount = 35;
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, $ancount, 0, 0);
		$response .= $question;
		for my $rr (0..$ancount-1) {
			$response .= pack('n', 0xc00c)
				. pack('nnNn', 1, 1, 300 - ($rr % 5) * 50, 4)
				. pack('CCCC', 10, 0, 0, $rr + 1);
		}
		return $response;
	}
);

# Stream many-rrs — 10 answer RRs (RDATA=50 each, 62 bytes per RR)
# Total: 12 + 17 + 10*62 = 649 DNS, 651 TCP.  At buffer 512: only 7 RRs
# fit in 510 DNS bytes (434), 8th is incomplete → no-store.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8094),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my @ttls = (300, 280, 260, 240, 220, 120, 60, 30, 10, 5);
		my $ancount = 10;
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, $ancount, 0, 0);
		$response .= $question;
		for my $rr (0..$ancount-1) {
			$response .= pack('n', 0xc00c)
				. pack('nnNn', 1, 1, $ttls[$rr], 50)
				. ("\x00" x 50);
		}
		return $response;
	}
);

# Stream boundary exact — first RR RDATA=469 so it ends exactly at byte 510
# of the DNS message (the limit at buffer_size 512).
# Total: 12 + 17 + 481 + 16 + 16 = 542 DNS, 544 TCP.  At buffer 512:
# need=min(512,544)=512, 510 DNS.  First RR complete → TTL=300.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8095),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my @ttls = (300, 200, 100);
		my $ancount = 3;
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, $ancount, 0, 0);
		$response .= $question;
		# First RR: large RDATA to create boundary at 512
		$response .= pack('n', 0xc00c)
			. pack('nnNn', 1, 1, $ttls[0], 469)
			. ("\x00" x 469);
		# Second and third: normal small RRs
		for my $rr (1..$ancount-1) {
			$response .= pack('n', 0xc00c)
				. pack('nnNn', 1, 1, $ttls[$rr], 4)
				. pack('CCCC', 10, 0, 0, $rr + 1);
		}
		return $response;
	}
);

# Stream boundary not-streaming — 3 small RRs (16 bytes each)
# Total: 12 + 17 + 48 = 77 DNS, 79 TCP.  At buffer 512: entire response
# fits, no streaming.  All 3 RRs processed → min TTL = 100.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8096),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my @ttls = (300, 200, 100);
		my $ancount = 3;
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, $ancount, 0, 0);
		$response .= $question;
		for my $rr (0..$ancount-1) {
			$response .= pack('n', 0xc00c)
				. pack('nnNn', 1, 1, $ttls[$rr], 4)
				. pack('CCCC', 10, 0, 0, $rr + 1);
		}
		return $response;
	}
);

# SOA MINIMUM
$t->run_daemon(\&tcp_dns_daemon, $t, port(8097),
	sub { dns_soa_nxdomain_response($_[0], 3600, 900) });

# Auth malformed
$t->run_daemon(\&tcp_dns_daemon, $t, port(8098),
	sub { dns_nxdomain_auth_malformed_response($_[0]) });

# Auth truncated
$t->run_daemon(\&tcp_dns_daemon, $t, port(8099),
	sub { dns_nxdomain_auth_trunc_response($_[0]) });

# Auth rdlength overflow
$t->run_daemon(\&tcp_dns_daemon, $t, port(8100),
	sub { dns_nxdomain_auth_rdlen_overflow_response($_[0]) });

# Filter overflow — specialized daemon
$t->run_daemon(\&dns_filter_overflow_daemon, $t, port(8101));

# Label data overflow: answer name label extends past response end
$t->run_daemon(\&tcp_dns_daemon, $t, port(8102),
	sub {
		my ($query_data) = @_;
		my $qid = substr($query_data, 0, 2);
		my $qdcount = unpack('n', substr($query_data, 4, 2));
		return $qid . pack('nnnnn', 0x8180, $qdcount, 1, 0, 0)
			. "\x07example\x03com\x00\x00\x01\x00\x01"
			. "\x10";
	}
);

# No root label: name reaches buffer end without terminator
$t->run_daemon(\&tcp_dns_daemon, $t, port(8103),
	sub {
		my ($query_data) = @_;
		my $qid = substr($query_data, 0, 2);
		my $qdcount = unpack('n', substr($query_data, 4, 2));
		return $qid . pack('nnnnn', 0x8180, $qdcount, 1, 0, 0)
			. "\x07example\x03com\x00\x00\x01\x00\x01"
			. "\x03foo";
	}
);

# Question name overflow: skip_name fails in question section
$t->run_daemon(\&tcp_dns_daemon, $t, port(8104),
	sub {
		my ($query_data) = @_;
		my $qid = substr($query_data, 0, 2);
		return $qid . pack('nnnnn', 0x8180, 1, 0, 0, 0)
			. "\x10";
	}
);

# SOA RDLENGTH overflow: RDLENGTH claims more RDATA than present,
# with valid MNAME/RNAME so skip_name succeeds past buffer end
$t->run_daemon(\&tcp_dns_daemon, $t, port(8105),
	sub { dns_soa_rdlen_oob_response($_[0]) });

# TTL overflow: answer section with TTL > 2^31-1
$t->run_daemon(\&tcp_dns_daemon, $t, port(8106),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 1, 0, 0);
		$response .= $question;
		$response .= pack('n', 0xc00c) . pack('nn', 1, 1)
				. pack('N', 0x80000001)  # TTL > 2^31-1 (invalid per RFC 2181)
				. pack('n', 4)
				. pack('CCCC', 127, 0, 0, 1);
		return $response;
	}
);

# SOA MINIMUM overflow: NXDOMAIN with SOA MINIMUM field > 2^31-1
$t->run_daemon(\&tcp_dns_daemon, $t, port(8107),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);
		$response .= $question;
		my $soa_name = pack('C', 0);
		my $mname = pack('C', 7) . 'example' . pack('C', 3) . 'com'
				. pack('C', 0);
		my $rname = pack('C', 4) . 'host' . $mname;
		my $soa_rdata = $mname . $rname
					. pack('NNNNN', 1, 3600, 900, 604800, 0x80000001);
		my $soa = $soa_name
				. pack('nnNn', 6, 1, 3600, length($soa_rdata))
				. $soa_rdata;
		$response .= $soa;
		return $response;
	}
);

# SOA MNAME-only: rdlength equals MNAME length, so after skip_name for
# MNAME, rp == soa_end and the second skip_name (RNAME) is called with
# *p == end — the while loop in skip_name is never entered, and the
# fallthrough "return NGX_ERROR" at the bottom is reached.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8108),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8183, $qdcount, 0, 1, 0);
		$response .= $question;
		my $soa_name = pack('C', 0);
		my $mname = pack('C', 7) . 'example' . pack('C', 3) . 'com'
				. pack('C', 0);
		my $soa = $soa_name
				. pack('nnNn', 6, 1, 3600, length($mname))
				. $mname;
		$response .= $soa;
		return $response;
	}
);

# Stream boundary 1-byte-over — first RR RDATA=470 so it ends 1 byte past
# the 510-byte DNS limit at buffer_size 512.
# Total: 12 + 17 + 482 + 16 + 16 = 543 DNS, 545 TCP.  At buffer 512:
# need=min(512,545)=512, 510 DNS.  First RR incomplete (needs 470, has 469)
# → no-store.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8109),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my @ttls = (300, 200, 100);
		my $ancount = 3;
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, $ancount, 0, 0);
		$response .= $question;
		# First RR: RDATA 1 byte larger than exact-fit boundary
		$response .= pack('n', 0xc00c)
			. pack('nnNn', 1, 1, $ttls[0], 470)
			. ("\x00" x 470);
		for my $rr (1..$ancount-1) {
			$response .= pack('n', 0xc00c)
				. pack('nnNn', 1, 1, $ttls[$rr], 4)
				. pack('CCCC', 10, 0, 0, $rr + 1);
		}
		return $response;
	}
);

# Stream boundary ttl-fit-rdata-cut — 2 RRs: first RDATA=455 (TTL=300),
# second RDATA=4 (TTL=100).  Total: 12 + 17 + 467 + 16 = 512 DNS, 514 TCP.
# At buffer 512: need=min(512,514)=512, 510 DNS.  First RR complete.
# Second RR: TTL fits at bytes 500-503, RDLENGTH=4, but only 2 RDATA bytes
# available → incomplete → no-store.
$t->run_daemon(\&tcp_dns_daemon, $t, port(8110),
	sub {
		my ($query_data) = @_;
		my ($id, $flags, $qdcount) = unpack('nnn', $query_data);
		my ($question, $offset) = copy_question_section($query_data);
		my $response = pack('nnnnnn', $id, 0x8180, $qdcount, 2, 0, 0);
		$response .= $question;
		# First RR: large RDATA, TTL=300
		$response .= pack('n', 0xc00c)
			. pack('nnNn', 1, 1, 300, 455)
			. ("\x00" x 455);
		# Second RR: TTL=100, RDATA=4 — TTL fits but RDATA cut
		# at buffer boundary
		$response .= pack('n', 0xc00c)
			. pack('nnNn', 1, 1, 100, 4)
			. pack('CCCC', 10, 0, 0, 1);
		return $response;
	}
);

$t->run();

# Wait for all daemons to be ready
for my $p (8081 .. 8110) {
	$t->waitforsocket('127.0.0.1:' . port($p));
}
$t->waitforsocket('127.0.0.1:' . port(9081), 'udp');

###############################################################################

my $query = dns_query('example.com', 1);

subtest 'Cache-Control' => sub {
	my $resp = doh_post('/dns-query', $query);
	like($resp, qr/Cache-Control: max-age=300/i,
		'Cache-Control matches DNS TTL');

	# Multi-answer min TTL
	my $multi_query = dns_query('multi.example.com', 1);
	$resp = doh_post('/dns-query', $multi_query);
	like($resp, qr/Cache-Control: max-age=300/i,
		'Multi-answer min TTL Cache-Control');

	# NXDOMAIN: Cache-Control from SOA authority
	$resp = doh_post('/dns-query-nxdomain', $query);
	like($resp, qr/Cache-Control: max-age=3600/i,
		'No-answer Cache-Control from SOA authority section');

	# UDP Cache-Control TTL=300
	$resp = doh_post('/dns-query-udp', $query);
	like($resp, qr/Cache-Control: max-age=300/i,
		'UDP Cache-Control matches DNS TTL (streaming safe)');
};

like(doh_post('/dns-query-no-answer', $query), qr/HTTP\/1\.. 200/,
	'DNS no-answer response - 200');

like(doh_post('/dns-query-malformed', $query), qr/HTTP\/1\.. 200/,
	'Malformed DNS response - 200');

like(doh_post('/dns-query-trunc-qtype', $query), qr/HTTP\/1\.. 200/,
	'Truncated QTYPE+QCLASS in question - 200');

like(doh_post('/dns-query-trunc-answer', $query), qr/HTTP\/1\.. 200/,
	'Truncated answer section - 200');

subtest 'Fake ancount -> no-store' => sub {
	my $resp = doh_post('/dns-query-fake-ancount', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Fake ancount response - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Fake ancount produces no-store');
};

# Label 0x80 -> 200 + no-store
subtest 'Label 0x80 in answer name' => sub {
	my $resp = doh_post('/dns-query-label-0x80', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Label 0x80 in answer - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Label 0x80: no-store (safe default)');
};

subtest 'Multi-TTL: min(60, 300) = 60' => sub {
	my $resp = doh_post('/dns-query-multi-ttl', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Multi-TTL answer - 200');
	like($resp, qr/Cache-Control: max-age=60/i,
		'Multi-TTL answer: min TTL (60) selected over 300');
};

subtest 'RDLENGTH=0: TTL extracted correctly (=42)' => sub {
	my $resp = doh_post('/dns-query-rdlength0', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'RDLENGTH=0 answer - 200');
	like($resp, qr/Cache-Control: max-age=42/i,
		'RDLENGTH=0: TTL extracted correctly');
};

subtest 'Uncompressed names' => sub {
	my $resp = doh_post('/dns-query-uncompressed', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Uncompressed names response - 200');
	like($resp, qr/Cache-Control: max-age=\d+/i,
		'Uncompressed names Cache-Control present');
};

# TCP streaming: answer fits -> TTL=300 (subtest)
subtest 'TCP streaming: answer fits' => sub {
	my $resp = doh_post('/dns-query-stream-answer-fits', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TCP streaming answer-fits - 200');
	like($resp, qr/Content-Type: application\/dns-message/i,
		'TCP streaming answer-fits - correct content type');
	like($resp, qr/Cache-Control: max-age=300/i,
		'TCP streaming answer-fits - TTL extracted from buffer');

	my $body = doh_extract_body($resp);
	if ($body) {
		my ($resp_id) = unpack('n', $body);
		my ($orig_id) = unpack('n', $query);
		is($resp_id, $orig_id, 'TCP streaming preserves original query ID');
	} else {
		fail('TCP streaming preserves original query ID - no body');
	}
};

subtest 'TCP streaming' => sub {
	my $resp = doh_post('/dns-query-stream-answer-no-fit', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TCP streaming answer-no-fit - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'TCP streaming answer-no-fit - TTL=0 (answer truncated)');

	$resp = doh_post('/dns-query-stream-many-rrs', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TCP streaming many-rrs - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'TCP streaming many-rrs - TTL=0 (not all RRs fit)');
};

subtest 'Streaming boundary' => sub {
	my $resp = doh_post('/dns-query-stream-boundary-exact', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Boundary exact-fit - 200');
	like($resp, qr/Cache-Control: max-age=300/i,
		'Boundary exact-fit - TTL extracted');

	$resp = doh_post('/dns-query-stream-boundary-1byte-over', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Boundary 1-byte-over - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Boundary 1-byte-over - TTL=0');

	$resp = doh_post('/dns-query-stream-boundary-not-streaming', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Boundary not-streaming - 200');
	like($resp, qr/Cache-Control: max-age=100/i,
		'Boundary not-streaming - TTL extracted (normal path)');

	$resp = doh_post('/dns-query-stream-boundary-ttl-fit-rdata-cut', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Boundary TTL-fit-RDATA-cut - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Boundary TTL-fit-RDATA-cut - TTL=0 (RR incomplete)');
};

like(doh_post('/dns-query-soa-minimum', $query),
	qr/Cache-Control: max-age=900/i,
	'SOA MINIMUM < TTL: max-age=900');

# Authority section edge cases (subtest)
subtest 'Authority section edge cases' => sub {
	my $resp = doh_post('/dns-query-auth-malformed', $query);
	like($resp, qr/Cache-Control: no-store/i, 'Malformed authority: no-store');

	$resp = doh_post('/dns-query-auth-trunc', $query);
	like($resp, qr/Cache-Control: no-store/i, 'Truncated authority: no-store');

	$resp = doh_post('/dns-query-auth-rdlen-overflow', $query);
	like($resp, qr/Cache-Control: no-store/i,
		'Authority rdlength overflow: no-store');
};

subtest 'Filter overflow' => sub {
	my $resp = doh_post('/dns-query-filter-overflow', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Filter overflow: 200');
	like($resp, qr/application\/dns-message/,
		'Filter overflow: DNS content type');
};

subtest 'extract_min_ttl: label data extends past buffer end' => sub {
	my $resp = doh_post('/dns-query-label-overflow', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Label overflow: 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Label overflow: no-store');
};

subtest 'extract_min_ttl: name reaches end without root label' => sub {
	my $resp = doh_post('/dns-query-no-root-label', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'No root label: 200');
	like($resp, qr/Cache-Control: no-store/i,
		'No root label: no-store');
};

subtest 'extract_min_ttl: question QTYPE+QCLASS overflow' => sub {
	my $resp = doh_post('/dns-query-question-overflow', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Question overflow: 200');
	like($resp, qr/Cache-Control: no-store/i,
		'Question overflow: no-store');
};

# Large doh_max_size -> 200
{
	my $resp = doh_post('/dns-query-max-size-large', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'Large max_size: 200');
}

subtest 'SOA RDLENGTH OOB: RDLENGTH exceeds remaining buffer' => sub {
	my $resp = doh_post('/dns-query-soa-rdlen-oob', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'SOA RDLENGTH OOB: 200');
	like($resp, qr/Cache-Control: no-store/i,
		'SOA RDLENGTH OOB: no-store');
};

# TTL overflow in answer section: TTL > 2^31-1 (RFC 2181 §8)
subtest 'TTL overflow in answer section' => sub {
	my $resp = doh_post('/dns-query-ttl-overflow', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'TTL overflow answer - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'TTL overflow answer: no-store (invalid TTL treated as 0)');
};

# SOA MINIMUM overflow: MINIMUM field > 2^31-1 in authority section
subtest 'SOA MINIMUM overflow' => sub {
	my $resp = doh_post('/dns-query-soa-minimum-overflow', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'SOA MINIMUM overflow - 200');
	like($resp, qr/Cache-Control: no-store/i,
		'SOA MINIMUM overflow: no-store (invalid MINIMUM treated as 0)');
};

# SOA MNAME-only: rdlength = MNAME length, skip_name fallthrough
subtest 'SOA MNAME-only (skip_name fallthrough)' => sub {
	my $resp = doh_post('/dns-query-soa-mname-only', $query);
	like($resp, qr/HTTP\/1\.. 200/, 'SOA MNAME-only - 200');
	like($resp, qr/Cache-Control: max-age=3600/i,
		'SOA MNAME-only: max-age from SOA TTL (RNAME skipped)');
};

###############################################################################
# Specialized daemons

sub dns_filter_overflow_daemon {
	my ($t, $port) = @_;

	my $server = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create DNS filter overflow server socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $buf = read_tcp_query($client);
		next unless defined $buf;

		my $response = dns_response($buf, '127.0.0.1', 300);
		# Send response with trailing garbage to test the
		# bytes > u->length truncation in the filter.
		send_tcp_response($client, $response . "EXTRA");
		$client->close;
	}
}
