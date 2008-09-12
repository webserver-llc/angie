package Test::Nginx::SMTP;

# (C) Maxim Dounin

# Module for nginx smtp tests.

###############################################################################

use warnings;
use strict;

use Test::More qw//;
use IO::Socket;
use Socket qw/ CRLF /;

use Test::Nginx;

use base qw/ IO::Socket::INET /;

sub new {
	my $class = shift;

	my $self = return $class->SUPER::new(
		Proto => "tcp",
		PeerAddr => "localhost",
		PeerPort => 10025,
		@_
	)
		or die "Can't connect to nginx: $!\n";

	$self->autoflush(1);

	return $self;
}

sub send {
	my ($self, $cmd) = @_;
	log_out($cmd);
	$self->print($cmd . CRLF);
}

sub read {
	my ($self) = @_;
	eval {
		alarm(2);
		local $SIG{ALRM} = sub { die "alarm\n" };
		while (<$self>) {
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

sub check {
	my ($self, $regex, $name) = @_;
	Test::More::like($self->read(), $regex, $name);
}

sub ok {
	my $self = shift; 
	$self->check(qr/^2\d\d /, @_);
}

###############################################################################

1;

###############################################################################
