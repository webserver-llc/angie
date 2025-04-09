#!/usr/bin/perl

# (C) 2024 Web Server LLC

# Tests for resolver "sent" statistics.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::SMTP;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api mail smtp rewrite upstream_zone/)->plan(10)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http    http://127.0.0.1:8081/mail/auth;
    smtp_auth    none;
    server_name  locahost;

    proxy_timeout 15s;

    # prevent useless resend
    resolver_timeout 10s;

    server {
        listen    127.0.0.1:8025;
        protocol  smtp;
        resolver  127.0.0.1:%%PORT_8070_UDP%% status_zone=rzone;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8070_UDP%% status_zone=rzone;

    upstream u {
        zone u 1m;
        server example.com service=example resolve;
    }

    server {
        listen 127.0.0.1:8091;

        location / {
            return 200;
        }
    }

    server {
        listen 127.0.0.1:8092;
        server_name  localhost;

        location / {
            proxy_pass http://u;
        }
    }

    server {
        listen 127.0.0.1:8080;
        server_name  localhost;

        location /api/ {
            api /;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location = /mail/auth {
            set $reply $http_client_host;

            if ($http_client_host !~ UNAVAIL) {
                set $reply OK;
            }

            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port %%PORT_8026%%;
            return 204;
        }
    }
}

EOF

$t->run_daemon(\&Test::Nginx::SMTP::smtp_test_daemon);
$t->run_daemon(\&dns_daemon, port(8070), $t);

$t->run();

$t->waitforsocket('127.0.0.1:' . port(8026));
$t->waitforfile($t->testdir . '/' . port(8070));

###############################################################################

# wait for nginx resolver to complete query
for (1 .. 50) {
	last if get('/', 8092) =~ qr /200 OK/;
	select undef, undef, undef, 0.1;
}

my $j = get_json("/api/status/resolvers/rzone");

is($j->{sent}{a}, 1, 'First A type');
is($j->{sent}{aaaa}, 1, 'First AAAA type');
is($j->{sent}{srv}, 1, 'First SRV type');
is($j->{sent}{ptr}, 0, 'First PTR type');

my $s = Test::Nginx::SMTP->new();
my $s2 = Test::Nginx::SMTP->new();

$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('MAIL FROM:<test@example.com> SIZE=100');
$s->read();

$s->send('RCPT TO:<test@example.com>');
$s->ok('PTR');

$s->send('QUIT');
$s->read();

$s2->read();
$s2->send('EHLO example.com');
$s2->ok('PTR waiting');

$j = get_json("/api/status/resolvers/rzone");

is($j->{sent}{a}, 2, 'Second A type');
is($j->{sent}{aaaa}, 2, 'Second AAAA type');
is($j->{sent}{srv}, 1, 'Second SRV type');
is($j->{sent}{ptr}, 1, 'Second PTR type');

###############################################################################

sub reply_handler {
	my ($recv_data, $port) = @_;

	my (@name, @rdata);

	use constant NOERROR	=> 0;

	use constant A		=> 1;
	use constant CNAME	=> 5;
	use constant PTR	=> 12;
	use constant AAAA	=> 28;
	use constant SRV	=> 33;
	use constant DNAME	=> 39;

	use constant IN		=> 1;

	# default values

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

	# decode name

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);
	my $name = join('.', @name);

	if ($type == A) {
		push @rdata, rd_addr($ttl, '127.0.0.1');

	} elsif ($type == AAAA) {
		push @rdata, rd_addr6($ttl, 'fe80::1');

	} elsif ($type == SRV) {
		push @rdata, rd_srv($ttl, 'example.com');

	} elsif ($type == PTR) {
		push @rdata, rd_name($ttl, 'example.com');
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub expand_ip6 {
	my ($addr) = @_;

	substr ($addr, index($addr, "::"), 2) =
		join "0", map { ":" } (0 .. 8 - (split /:/, $addr) + 1);
	map { hex "0" x (4 - length $_) . "$_" } split /:/, $addr;
}

sub get {
	my ($location, $port) = @_;
	return http_get("$location", PeerAddr => '127.0.0.1:' . port($port));
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	# use a special pack string to not zero pad

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub rd_addr6 {
	my ($ttl, $addr) = @_;

	pack 'n3N nn8', 0xc00c, AAAA, IN, $ttl, 16, expand_ip6($addr);
}

sub rd_srv {
	my ($ttl, $srv) = @_;
	my ($rdlen, @rdname);

	use constant PORT	=> port(8091);
	use constant WEIGHT	=> 0;
	use constant PRIORITY	=> 5;

	@rdname = split /\./, $srv;
	$rdlen = length(join '', @rdname) + @rdname + 1;

	pack("n3N n4(C/a*)* x", 0xc00c, SRV, IN, $ttl, $rdlen, PRIORITY,
		WEIGHT, PORT, @rdname);
}

sub rd_name {
	my ($ttl, $name) = @_;
	my ($rdlen, @rdname);

	@rdname = split /\./, $name;
	$rdlen = length(join '', @rdname) + @rdname + 1;

	pack("n3N n(C/a*)* x", 0xc00c, PTR, IN, $ttl, $rdlen, @rdname);
}

sub dns_daemon {
	my ($port, $t) = @_;

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (1) {
		$socket->recv($recv_data, 65536);
		$data = reply_handler($recv_data, $port);
		$socket->send($data);
	}
}

###############################################################################
