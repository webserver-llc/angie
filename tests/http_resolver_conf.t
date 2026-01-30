#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for http resolver resolv.conf.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'must be root') if $> != 0;
plan(skip_all => '127.0.1.* local addresses required') if $^O eq 'freebsd';

my $t = Test::Nginx->new({can_root => 1})->has(qw/http proxy rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

user root;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       %%PORT_8080%%;
        server_name  localhost;

        location /both {
            resolver    127.0.1.2:53 127.0.1.3:53
                            conf=%%TESTDIR%%/resolv.conf valid=1s;
            proxy_pass  http://$host:%%PORT_8080%%/backend;
        }

        location /conf {
            resolver    conf=%%TESTDIR%%/resolv.conf valid=1s;
            proxy_pass  http://$host:%%PORT_8080%%/backend;
        }

        location /conf_late {
            resolver    conf=%%TESTDIR%%/late_resolv.conf valid=1s;
            proxy_pass  http://$host:%%PORT_8080%%/backend;
        }

        location /default {
            resolver    conf=%%TESTDIR%%/default_resolv.conf valid=1s;
            proxy_pass  http://$host:%%PORT_8080%%/backend;
        }

        location /backend {
            return 200;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, '127.0.0.1', $t);
$t->run_daemon(\&dns_daemon, '127.0.1.2', $t);
$t->run_daemon(\&dns_daemon, '127.0.1.3', $t);
$t->run_daemon(\&dns_daemon, '127.0.1.4', $t);
$t->run_daemon(\&dns_daemon, '127.0.1.5', $t);

$t->write_file('resolv.conf', "nameserver 127.0.1.4\nnameserver 127.0.1.5\n");

$t->write_file('default_resolv.conf',
	"nameserver 127.0.0.1\nnameserver 127.0.0.2\n");

$t->write_file('late_resolv.conf', "\n");

$t->run()->plan(16);

$t->waitforfile($t->testdir . '/127.0.0.1');
$t->waitforfile($t->testdir . '/127.0.1.2');
$t->waitforfile($t->testdir . '/127.0.1.3');
$t->waitforfile($t->testdir . '/127.0.1.4');
$t->waitforfile($t->testdir . '/127.0.1.5');

###############################################################################

$t->write_file('late_resolv.conf', "nameserver 127.0.1.2\n");

like(http_get('/conf_late', host => '2-test.com'), qr/200 OK/,
	'/conf_late resolver 127.0.1.2');

like(http_get('/both', host => '2-test.com'), qr/200 OK/,
	'/both resolver 127.0.1.2');
like(http_get('/both', host => '3-test.com'), qr/200 OK/,
	'/both resolver 127.0.1.3');
like(http_get('/both', host => '4-test.com'), qr/200 OK/,
	'/both resolver 127.0.1.4');
like(http_get('/both', host => '5-test.com'), qr/200 OK/,
	'/both resolver 127.0.1.5');

like(http_get('/conf', host => '4-test.com'), qr/200 OK/,
	'/conf resolver 127.0.1.4');
like(http_get('/conf', host => '5-test.com'), qr/200 OK/,
	'/conf resolver 127.0.1.5');

sleep 2;

$t->write_file('resolv.conf', "nameserver 127.0.1.5\n");

like(http_get('/both', host => '2-test.com'), qr/200 OK/,
	'2nd /both resolver 127.0.1.2');
like(http_get('/both', host => '3-test.com'), qr/200 OK/,
	'2nd /both resolver 127.0.1.3');
like(http_get('/both', host => '4-test.com'), qr/502/,
	'2nd /both no resolver 127.0.1.4');

sleep 2;

like(http_get('/both', host => '2-test.com'), qr/200 OK/,
	'3d /both resolver 127.0.1.2');

like(http_get('/conf', host => '4-test.com'), qr/502/,
	'2nd /conf no resolver 127.0.1.4');
like(http_get('/conf', host => '5-test.com'), qr/200 OK/,
	'2nd /conf resolver 127.0.1.5');

like(http_get('/default', host => 'default-test.com'), qr/200 OK/,
	'/default resolver 127.0.0.1');

sleep 2;

$t->write_file('default_resolv.conf', "\n");

like(http_get('/default', host => 'default-test.com'), qr/200 OK/,
	'1st /default resolver 127.0.0.1');
like(http_get('/default', host => 'default-test.com'), qr/200 OK/,
	'2nd /default resolver 127.0.0.1');

###############################################################################

sub reply_handler {
	my ($recv_data, $addr, $port, $state, %extra) = @_;

	my (@name, @rdata);

	use constant NOERROR	=> 0;
	use constant FORMERR	=> 1;
	use constant SERVFAIL	=> 2;
	use constant NXDOMAIN	=> 3;

	use constant A		=> 1;
	use constant CNAME	=> 5;
	use constant DNAME	=> 39;

	use constant IN		=> 1;

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 0);

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
	if ((($name eq '2-test.com') && ($addr eq '127.0.1.2')) ||
		(($name eq '3-test.com') && ($addr eq '127.0.1.3')) ||
		(($name eq '4-test.com') && ($addr eq '127.0.1.4')) ||
		(($name eq '5-test.com') && ($addr eq '127.0.1.5')) ||
		(($name eq 'default-test.com') && ($addr eq '127.0.0.1')))
	{
		if ($type == A || $type == CNAME) {
			push @rdata, rd_addr($ttl, '127.0.1.1');
		}
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
	my ($addr, $t, %extra) = @_;
	my $port = 53;

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr => $addr,
		LocalPort => $port,
		Proto => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($socket);

	local $SIG{PIPE} = 'IGNORE';

	my %state = (
		cnamecnt	=> 0,
		twocnt		=> 0,
		ttlcnt		=> 0,
		ttl0cnt		=> 0,
		cttlcnt		=> 0,
		cttl2cnt	=> 0,
		manycnt		=> 0,
		casecnt		=> 0,
		idcnt		=> 0,
		fecnt		=> 0,
	);

	open my $fh, '>', $t->testdir() . '/' . $addr;
	close $fh;

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($socket == $fh) {
				$fh->recv($recv_data, 65536);
				$data = reply_handler($recv_data, $addr, $port,
					\%state);
				$fh->send($data);

			} else {
				$fh->recv($recv_data, 65536);
				unless (length $recv_data) {
					$sel->remove($fh);
					$fh->close;
					next;
				}

again:
				my $len = unpack("n", $recv_data);
				$data = substr $recv_data, 2, $len;
				$data = reply_handler($data, $addr, $port, \%state,
					tcp => 1);
				$data = pack("n", length $data) . $data;
				$fh->send($data);
				$recv_data = substr $recv_data, 2 + $len;
				goto again if length $recv_data;
			}
		}
	}
}

###############################################################################
