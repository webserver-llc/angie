package _common;

# (C) Maxim Dounin

# Generict module for nginx tests.

###############################################################################

use warnings;
use strict;

use base qw/ Exporter /;

our @EXPORT = qw/ start_nginx smtp_connect smtp_send smtp_read smtp_check
	smtp_ok log_in log_out CRLF http /;

###############################################################################

use Test::More;
use File::Temp qw/ tempdir /;
use IO::Socket;

use constant CRLF => "\x0D\x0A";

our $testdir;
our $s;

###############################################################################

# Create temp directory and run nginx instance.

sub start_nginx {
	my ($conf) = @_;

	$testdir = tempdir('nginx-test-XXXXXXXXXX', TMPDIR => 1, CLEANUP => 1)
		or die "Can't create temp directory: $!\n";

	system("cat $conf | sed 's!%%TESTDIR%%!$testdir!g' "
		. "> $testdir/nginx.conf");

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		exec('../nginx/objs/nginx', '-c', "$testdir/nginx.conf", '-g',
			"pid $testdir/nginx.pid; "
			. "error_log $testdir/nginx-error.log debug;")
			or die "Unable to exec(): $!\n";
	}

	# wait for nginx to start

	sleep 1;
}

sub stop_nginx {
	# terminate nginx by SIGTERM
	kill 15, `cat $testdir/nginx.pid`;
	wait;
}

END {
	stop_nginx();
}

###############################################################################

sub log_out {
	my ($msg) = @_;
	$msg =~ s/^/# >> /gm;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

sub log_in {
	my ($msg) = @_;
	$msg =~ s/^/# << /gm;
	$msg =~ s/([\x00-\x1f\x7f-])/sprintf('\\x%02x', ord($1)) . (($1 eq "\n") ? "\n" : '')/gmxe;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

###############################################################################

sub http {
	my ($request) = @_;
	my $reply;
	eval {
		local $SIG{ALRM} = sub { die "alarm\n" };
		alarm(2);
		my $s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerHost => 'localhost:8080'
		);
		log_out($request);
		$s->print($request);
		local $/;
		$reply = $s->getline();
		log_in($reply);
		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in('(timeout)');
		return undef;
	}
	return $reply;
}

###############################################################################

sub smtp_connect {
	$s = IO::Socket::INET->new(
		Proto => "tcp",
		PeerAddr => "localhost",
		PeerPort => 10025,
		@_
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

1;

###############################################################################
