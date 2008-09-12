package Test::Nginx;

# (C) Maxim Dounin

# Generict module for nginx tests.

###############################################################################

use warnings;
use strict;

use base qw/ Exporter /;

our @EXPORT = qw/ log_in log_out http /;

###############################################################################

use File::Temp qw/ tempdir /;
use IO::Socket;
use Socket qw/ CRLF /;

###############################################################################

sub new {
	my $self = {};
	bless $self;

	$self->{_testdir} = tempdir(
		'nginx-test-XXXXXXXXXX',
		TMPDIR => 1,
		CLEANUP => not $ENV{LEAVE}
	)
		or die "Can't create temp directory: $!\n";

	return $self;
}

sub DESTROY {
	my ($self) = @_;
	$self->stop();
}

sub run {
	my ($self, $conf) = @_;

	my $testdir = $self->{_testdir};

	if (defined $conf) {
		my $c = `cat $conf`;
		$self->write_file_expand('nginx.conf', $c);
	}

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

	return $self;
}

sub stop() {
	my ($self) = @_;

	# terminate nginx by SIGTERM
	kill 15, `cat $self->{_testdir}/nginx.pid`;
	wait;

	return $self;
}

sub write_file($$) {
	my ($self, $name, $content) = @_;

	open F, '>' . $self->{_testdir} . '/' . $name
		or die "Can't create $name: $!";
	print F $content;
	close F;

	return $self;
}

sub write_file_expand($$) {
	my ($self, $name, $content) = @_;

	$content =~ s/%%TESTDIR%%/$self->{_testdir}/gms;

	return $self->write_file($name, $content);
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
	$msg =~ s/([^\x20-\x7e])/sprintf('\\x%02x', ord($1)) . (($1 eq "\n") ? "\n" : '')/gmxe;
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

1;

###############################################################################
