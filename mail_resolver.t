#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for mail resolver.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

eval { require Net::DNS::Nameserver; };
plan(skip_all => "Net::DNS::Nameserver not installed") if $@;

my $t = Test::Nginx->new()->has(qw/mail smtp http rewrite/)
	->run_daemon(\&Test::Nginx::SMTP::smtp_test_daemon);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http    http://127.0.0.1:8080/mail/auth;
    smtp_auth    none;
    server_name  locahost;

    server {
        listen    127.0.0.1:8025;
        protocol  smtp;
        resolver  127.0.0.1:8081 127.0.0.1:8082 127.0.0.1:8083;
    }

    server {
        listen    127.0.0.1:8027;
        protocol  smtp;
        resolver  127.0.0.1:8082;
    }

    server {
        listen    127.0.0.1:8028;
        protocol  smtp;
        resolver  127.0.0.1:8083;

        # prevent useless resend
        resolver_timeout 1s;
    }

    server {
        listen    127.0.0.1:8029;
        protocol  smtp;
        resolver  127.0.0.1:8084;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /mail/auth {
            set $reply $http_client_host;

            if ($http_client_host !~ UNAVAIL) {
                set $reply OK;
            }

            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port 8026;
            return 204;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, 8081);
$t->run_daemon(\&dns_daemon, 8082);
$t->run_daemon(\&dns_daemon, 8083);
$t->run_daemon(\&dns_daemon, 8084);
$t->run();

$t->waitforsocket('127.0.0.1:8081');
$t->waitforsocket('127.0.0.1:8082');
$t->waitforsocket('127.0.0.1:8083');
$t->waitforsocket('127.0.0.1:8084');

$t->plan(5);

###############################################################################

# PTR

my $s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->ok('PTR');

$s->send('QUIT');
$s->read();
close $s;

# Cached PTR prevents from querying bad ns on port 8083

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->ok('PTR cached');

$s->send('QUIT');
$s->read();
close $s;

# SERVFAIL

$s = Test::Nginx::SMTP->new(PeerAddr => "127.0.0.1:8027");
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->check(qr/TEMPUNAVAIL/, 'PTR SERVFAIL');

$s->send('QUIT');
$s->read();
close $s;

# PTR with zero length RDATA

TODO: {
local $TODO = 'not yet';

$s = Test::Nginx::SMTP->new(PeerAddr => "127.0.0.1:8028");
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->check(qr/TEMPUNAVAIL/, 'PTR empty');

$s->send('QUIT');
$s->read();
close $s;

}

# CNAME

TODO: {
local $TODO = 'support for CNAME RR';

$s = Test::Nginx::SMTP->new(PeerAddr => "127.0.0.1:8029");
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->ok('PTR with CNAME');

$s->send('QUIT');
$s->read();
close $s;

}

###############################################################################

sub reply_handler {
	my ($name, $class, $type, $peerhost, $query, $conn) = @_;
	my ($rcode, @ans, $ttl, $rdata);

	$rcode = 'NOERROR';
	$ttl = 3600;

	if ($name eq 'a.example.net' && $type eq 'A') {
		($rdata) = ('127.0.0.1');
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} elsif ($name eq '1.0.0.127.in-addr.arpa' && $type eq 'PTR') {
		if ($conn->{sockport} == 8081) {
			$rdata = 'a.example.net';
			push @ans, Net::DNS::RR->new(
				"$name $ttl $class $type $rdata"
			);

		} elsif ($conn->{sockport} == 8082) {
			return 'SERVFAIL';

		} elsif ($conn->{sockport} == 8083) {
			# zero length RDATA
			$rdata = '';
			push @ans, Net::DNS::RR->new(
				"$name $ttl $class $type $rdata"
			);

		} elsif ($conn->{sockport} == 8084) {
			# PTR answered with CNAME
			($type, $rdata) = ('CNAME',
				'1.1.0.0.127.in-addr.arpa');
			push @ans, Net::DNS::RR->new(
				"$name $ttl $class $type $rdata"
			);
		}

	} elsif ($name eq '1.1.0.0.127.in-addr.arpa' && $type eq 'PTR') {
		$rdata = 'a.example.net';
		push @ans, Net::DNS::RR->new("$name $ttl $class $type $rdata");

	} else {
		$rcode = 'NXDOMAIN';
	}

	return ($rcode, \@ans);
}

sub dns_daemon {
	my ($port) = @_;

	my $ns = Net::DNS::Nameserver->new(
		LocalAddr    => '127.0.0.1',
		LocalPort    => $port,
		Proto        => 'udp',
		ReplyHandler => \&reply_handler,
	)
		or die "Can't create nameserver object: $!\n";

	$ns->main_loop;
}

###############################################################################
