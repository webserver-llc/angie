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
use Test::More qw//;

###############################################################################

our $NGINX = '../nginx/objs/nginx';

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

sub has {
	my ($self, $feature, %options) = @_;
	Test::More::plan(skip_all => "$feature not compiled in")
		unless `$NGINX -V 2>&1` =~ $feature;
	Test::More::plan($options{plan}) if defined $options{plan};
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
		exec($NGINX, '-c', "$testdir/nginx.conf", '-g',
			"pid $testdir/nginx.pid; "
			. "error_log $testdir/error.log debug;")
			or die "Unable to exec(): $!\n";
	}

	# wait for nginx to start

	sleep 1;

	$self->{_started} = 1;
	return $self;
}

sub stop() {
	my ($self) = @_;

	while ($self->{_daemons} && scalar @{$self->{_daemons}}) {
		my $p = shift @{$self->{_daemons}};
		kill 'TERM', $p;
		wait;
	}

	return $self unless $self->{_started};

	kill 'TERM', `cat $self->{_testdir}/nginx.pid`;
	wait;

	$self->{_started} = 0;

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

sub run_daemon($) {
	my ($self, $code) = @_;

	my $pid = fork();
	die "Can't fork daemon: $!\n" unless defined $pid;

	if ($pid == 0) {
		$code->();
		exit 0;
	}

	$self->{_daemons} = [] unless defined $self->{_daemons};
	push @{$self->{_daemons}}, $pid;

	return $self;
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
