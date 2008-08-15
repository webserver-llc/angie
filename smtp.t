#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx mail smtp module.

###############################################################################

use warnings;
use strict;

use Test::More tests => 24;

use IO::Socket;
use MIME::Base64;

use constant CRLF => "\x0D\x0A";

$| = 1;

my $s = smtp_connect();
smtp_check(qr/^220 /, "greeting");

smtp_send('EHLO example.com');
smtp_check(qr/^250 /, "ehlo");

smtp_send('AUTH PLAIN ' . encode_base64("test\@example.com\0\0bad", ''));
smtp_check(qr/^5.. /, 'auth plain with bad password');

smtp_send('AUTH PLAIN ' . encode_base64("test\@example.com\0\0secret", ''));
smtp_ok('auth plain');

# We are talking to backend from this point

smtp_send('MAIL FROM:<test@example.com> SIZE=100');
smtp_ok('mail from after auth');

smtp_send('RSET');
smtp_ok('rset');

smtp_send('MAIL FROM:<test@xn--e1afmkfd.xn--80akhbyknj4f> SIZE=100');
smtp_ok("idn mail from (example.test in russian)");

smtp_send('QUIT');
smtp_ok("quit");

# Try auth plain with pipelining

$s = smtp_connect();
smtp_check(qr/^220 /, "greeting");

smtp_send('EHLO example.com');
smtp_check(qr/^250 /, "ehlo");

TODO: {
	local $TODO = "pipelining not implemented yet";

	smtp_send('AUTH PLAIN '
		. encode_base64("test\@example.com\0\0bad", '') . CRLF
		. 'MAIL FROM:<test@example.com> SIZE=100');
	smtp_read();
	smtp_ok('mail from after failed pipelined auth');

	smtp_send('AUTH PLAIN '
		. encode_base64("test\@example.com\0\0secret", '') . CRLF
		. 'MAIL FROM:<test@example.com> SIZE=100');
	smtp_read();
	smtp_ok('mail from after pipelined auth');
}

# Try auth none

$s = smtp_connect();
smtp_check(qr/^220 /, "greeting");

smtp_send('EHLO example.com');
smtp_check(qr/^250 /, "ehlo");

smtp_send('MAIL FROM:<test@example.com> SIZE=100');
smtp_ok('auth none - mail from');

smtp_send('RCPT TO:<test@example.com>');
smtp_ok('auth none - rcpt to');

smtp_send('RSET');
smtp_ok('auth none - rset, should go to backend');

# Auth none with pipelining

$s = smtp_connect();
smtp_check(qr/^220 /, "greeting");

smtp_send('EHLO example.com');
smtp_check(qr/^250 /, "ehlo");

TODO: {
	smtp_send('MAIL FROM:<test@example.com> SIZE=100' . CRLF
		. 'RCPT TO:<test@example.com>' . CRLF
		. 'RSET');

	smtp_ok('pipelined mail from');

	local $TODO = "pipelining not implemented yet";

	smtp_ok('pipelined rcpt to');
	smtp_ok('pipelined rset');
}

# Connection must stay even if error returned to rcpt to command

$s = smtp_connect();
smtp_read(); # skip greeting

smtp_send('EHLO example.com');
smtp_read(); # skip ehlo reply

smtp_send('MAIL FROM:<test@example.com> SIZE=100');
smtp_read(); # skip mail from reply

smtp_send('RCPT TO:<example.com>');
smtp_check(qr/^5.. /, "bad rcpt to");

smtp_send('RCPT TO:<test@example.com>');
smtp_ok('good rcpt to');


###############################################################################

sub log_out {
	my ($msg) = @_;
	$msg =~ s/^/# >> /gm;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

sub log_in {
	my ($msg) = @_;
	$msg =~ s/\x0d/\\x0d/gm;
	$msg =~ s/\x0a/\\x0a/gm;
	print '# << ' . $msg . "\n";
}

sub smtp_connect {
	my $s = IO::Socket::INET->new(
		Proto => "tcp",
		PeerAddr => "localhost",
		PeerPort => 10025,
	)
		or die "Can't connect to nginx: $!\n";

	$s->autoflush(1);

	return $s;
}

sub smtp_send {
	my ($cmd) = @_;
	log_out($cmd);
	$s->print($cmd . CRLF);
}

sub smtp_read {
	my ($regex, $name) = @_;
	eval {
		alarm(2);
		local $SIG{ALRM} = sub { die "alarm\n" };
		while (<$s>) {
			log_in($_);
			next if m/^\d\d\d-/;
			last;
		}
		alarm(0);
	};
	alarm(0);
	if ($@) {
		return undef;
	}
	return $_;
}

sub smtp_check {
	my ($regex, $name) = @_;
	like(smtp_read(), $regex, $name);
}

sub smtp_ok {
	smtp_check(qr/^2\d\d /, @_);
}

###############################################################################
