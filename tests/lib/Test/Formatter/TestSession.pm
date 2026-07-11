#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Test Session class - results of a single test file execution

###############################################################################

package Test::Formatter::TestSession;

use strict;
use warnings;

use File::Basename;
use File::Temp qw /tempfile/ ;
use Test::Utils qw/trim :re/;
use Time::HiRes qw(time);

use base qw( TAP::Base );

BEGIN {
	my %PROPS= (
		test            => sub { shift; shift; },
		formatter       => sub { shift; shift; },
		parser          => sub { shift; shift; },
		results         => sub { shift; shift; },
		xresults        => sub { shift; shift; },
		tc_errors       => sub { shift; shift; },
		tc_misc         => sub { shift; shift; },
		meta            => sub { shift; shift; },
		closed          => sub { shift; shift; },
		tmp_fh          => sub { shift; shift; },
		tmp_fn          => sub { shift; shift; },
		orig_stderr     => sub { shift; shift; },
		err_lines       => sub { shift; shift; },
		curr_tc_num     => sub { shift; shift; },
		console_session => sub { shift; shift; },
		verbosity       => sub { shift; shift; },
		started_at      => sub { shift; shift; },
		start_wall      => sub { shift; shift; },
		start_user      => sub { shift; shift; },
		start_cuser     => sub { shift; shift; },
		start_system    => sub { shift; shift; },
		start_csystem   => sub { shift; shift; },
	);
	__PACKAGE__->mk_methods(keys %PROPS);
}


sub _initialize {
	my ($self, $args) = @_;

	$args ||= {};
	$self->SUPER::_initialize($args);

	$self->results([]);
	$self->xresults([]);
	$self->err_lines([]);
	$self->tc_errors({});
	$self->tc_misc({});
	$self->started_at(0);
	$self->meta({});
	$self->closed(0);
	$self->curr_tc_num(0);

	foreach my $arg (qw(test parser formatter console_session verbosity)) {
		$self->$arg($args->{$arg}) if defined $args->{$arg};
	}

	$self->start_wall(time());

	my ($user, $system, $cuser, $csystem) = times;

	$self->start_user($user);
	$self->start_cuser($cuser);
	$self->start_system($system);
	$self->start_csystem($csystem);

	return $self;
}


sub result {
	my ($self, $result) = @_;

	$self->console_session->result($result);

	if ($result->is_test) {

		$result->{test_status}  = $result->has_todo ? 'todo-' : '';
		$result->{test_status} .= $result->has_skip ? 'skip-' : '';
		$result->{test_status} .= $result->is_actual_ok ? 'ok' : 'not-ok';

		if ($result->has_skip) {
			$self->meta->{skipped}++;
		}

		if ($result->is_ok) {
			$self->meta->{passed}++;
		}

		if ($result->has_todo) {
			if ($result->is_actual_ok) {
				$result->{todo_passed} = 1;
			}
			$self->meta->{todo}++;
		}

		$self->curr_tc_num($self->curr_tc_num + 1);
	}

	push @{ $self->results }, $result;
	push @{ $self->xresults }, \%$result;
}


sub close_test {
	my ($self, @args) = @_;

	my $wall = time();
	my ($user, $system, $cuser, $csystem) = times;


	$self->{started_at} = $self->start_wall;
	$self->{time_wall} = $wall - $self->start_wall;
	$self->{time_user} = ($user - $self->start_user);
	$self->{time_user_child} = ($cuser - $self->start_cuser);
	$self->{time_user_total} =  $self->{time_user} + $self->{time_user_child};
	$self->{time_system} = $system - $self->start_system;
	$self->{time_system_child} = ($csystem - $self->start_csystem);
	$self->{time_system_total} = $self->{time_system} + $self->{time_system_child};
	$self->{time_process} = $self->{time_system_total} + $self->{time_user_total};

	# final results
	$self->console_session->close_test(@args);

	$self->closed(1);
}


sub session_report {
	my ($self) = @_;

	my $p = $self->parser;
	my $r = {
		test => $self->test,
		test_base => basename($self->test),
		xresults => $self->xresults,
		tc_errors => $self->tc_errors,
		tc_misc => $self->tc_misc,
		err_lines => $self->err_lines,
	};

	for my $key (qw(tests_planned tests_run start_time end_time skip_all
				skipped has_problems passed failed todo todo_passed
				actual_passed actual_failed wait exit))
	{
		$r->{$key} = $p->$key;
    }

	$r->{num_parse_errors} = scalar $p->parse_errors;
	$r->{parse_errors} = [ $p->parse_errors ];
	$r->{passed_tests} = [ $p->passed ];
	$r->{failed_tests} = [ $p->failed ];

	$r->{test_status} = $r->{has_problems} ? 'failed' : 'passed';
	$r->{elapsed_time} = $r->{end_time} - $r->{start_time};

	$r->{started_at} = $self->{started_at};
	$r->{time_wall} = $self->{time_wall};
	$r->{time_user} = $self->{time_user};
	$r->{time_user_child} = $self->{time_user_child};
	$r->{time_user_total} = $self->{time_user_total};
	$r->{time_system} = $self->{time_system};
	$r->{time_system_child} = $self->{time_system_child};
	$r->{time_system_total} = $self->{time_system_total};
	$r->{time_process} = $self->{time_process};

	return $r;
}

1;
