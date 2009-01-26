package Test::Nginx;

# (C) Maxim Dounin

# Generict module for nginx tests.

###############################################################################

use warnings;
use strict;

use base qw/ Exporter /;

our @EXPORT = qw/ log_in log_out http http_get http_head /;

###############################################################################

use File::Temp qw/ tempdir /;
use IO::Socket;
use Socket qw/ CRLF /;
use Test::More qw//;

###############################################################################

our $NGINX = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY}
	: '../nginx/objs/nginx';

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
	if ($ENV{TEST_NGINX_CATLOG}) {
		system("cat $self->{_testdir}/error.log");
	}
}

sub has {
	my ($self, $feature) = @_;

	my %regex = (
		mail	=> '--with-mail',
		flv	=> '--with-http_flv_module',
		rewrite	=> '(?s)^(?!.*--without-http_rewrite_module)',
	);

	Test::More::plan(skip_all => "$feature not compiled in")
		unless `$NGINX -V 2>&1` =~ $regex{$feature};

	return $self;
}

sub has_daemon($) {
	my ($self, $daemon) = @_;

	Test::More::plan(skip_all => "$daemon not found")
		unless `which $daemon`;

	return $self;
}

sub plan($) {
	my ($self, $plan) = @_;

	Test::More::plan(tests => $plan);

	return $self;
}

sub run(;$) {
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

	$self->waitforfile("$testdir/nginx.pid")
		or die "Can't start nginx";

	$self->{_started} = 1;
	return $self;
}

sub waitforfile($) {
	my ($self, $file) = @_;

	# wait for file to appear

	for (1 .. 30) {
		return 1 if -e $file;
		select undef, undef, undef, 0.1;
	}

	return undef;
}

sub waitforsocket($) {
	my ($self, $peer) = @_;

	# wait for socket to accept connections

	for (1 .. 30) {
		my $s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => $peer
		);

		return 1 if defined $s;

		select undef, undef, undef, 0.1;
	}

	return undef;
}

sub stop() {
	my ($self) = @_;

	while ($self->{_daemons} && scalar @{$self->{_daemons}}) {
		my $p = shift @{$self->{_daemons}};
		# SIGTERM to process group
		kill -15, $p;
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

sub run_daemon($;@) {
	my ($self, $code, @args) = @_;

	my $pid = fork();
	die "Can't fork daemon: $!\n" unless defined $pid;

	if ($pid == 0) {
		setpgrp(0, 0);
		if (ref($code) eq 'CODE') {
			$code->(@args);
			exit 0;
		} else {
			exec($code, @args);
		}
	}

	$self->{_daemons} = [] unless defined $self->{_daemons};
	push @{$self->{_daemons}}, $pid;

	return $self;
}

sub testdir() {
	my ($self) = @_;
	return $self->{_testdir};
}

###############################################################################

sub log_out {
	return unless $ENV{TEST_NGINX_VERBOSE};
	my ($msg) = @_;
	$msg =~ s/^/# >> /gm;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

sub log_in {
	return unless $ENV{TEST_NGINX_VERBOSE};
	my ($msg) = @_;
	$msg =~ s/^/# << /gm;
	$msg =~ s/([^\x20-\x7e])/sprintf('\\x%02x', ord($1)) . (($1 eq "\n") ? "\n" : '')/gmxe;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

###############################################################################

sub http_get($) {
	my ($url) = @_;
	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost

EOF
}

sub http_head($) {
	my ($url) = @_;
	return http(<<EOF);
HEAD $url HTTP/1.0
Host: localhost

EOF
}

sub http($) {
	my ($request) = @_;
	my $reply;
	eval {
		local $SIG{ALRM} = sub { die "alarm\n" };
		alarm(2);
		my $s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1:8080'
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
