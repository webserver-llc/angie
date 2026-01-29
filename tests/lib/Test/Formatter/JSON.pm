#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Test Formatter class: uses TAP::Formatter::Console to provide console
# output and additionally generates JSON report using the template

###############################################################################

package Test::Formatter::JSON;

use strict;
use warnings;

use Cwd;
use IO::File;
use File::Temp qw(tempdir);
use File::Spec::Functions qw(catdir);
use Test::Formatter::TestSession;
use TAP::Formatter::File;
use POSIX 'strftime';
use JSON;

use base qw(TAP::Base);

BEGIN {
	my %PROPS= (
		verbosity          => sub { shift; shift; },
		stdout             => sub { shift; shift; },
		output_fh          => sub { shift; shift; },
		session_class      => sub { shift; shift; },
		template_processor => sub { shift; shift; },
		template           => sub { shift; shift; },
		sessions           => sub { shift; shift; },
		tests              => sub { shift; shift; },
		console            => sub { shift; shift; }
	);
	__PACKAGE__->mk_methods(keys %PROPS);
}

sub _initialize {
	my ($class, $args) = @_;

	$args ||= {};
	my $self = $class->SUPER::_initialize($args);

	# may be overridden by prove opts
	$self->verbosity(0);
	$self->session_class('Test::Formatter::TestSession');
	$self->sessions([]);

	my $report_fn = strftime 'testreport-%Y%m%d_%H%M%S.json', localtime;

	$self->output_file($report_fn);

	# create a default formatter for display of text results
	# TODO: use Tap::Formatter::Console when run in real console
	# and Tap::Formatter::File when running redirected to file
	$self->console(TAP::Formatter::File->new($args));

	# consider args correct and pass them directly to base class
	foreach my $key (keys %$args) {
		$self->$key($args->{$key}) if ($self->can($key));
	}

	# quiet:  -1 // prove -q
	# normal:  0 // prove
	# verbose: 1 // prove - v
	my $fmt_verb = $ENV{TAP_FORMATTER_VERBOSITY} // 1;
	$self->verbosity($fmt_verb);

	return $self;
}


sub output_file {
	my ($self, $file) = @_;
	my $fh = IO::File->new( $file, 'w' ) or die "Error opening '$file' $!";
	$self->output_fh( $fh );
}


sub prepare {
	my ($self, @tests) = @_;
	$self->tests([@tests]);
	$self->console->prepare(@tests);
}


sub open_test {
	my ($self, $test, $parser) = @_;

	my $console_session = $self->console->open_test($test, $parser);

	my $session = $self->session_class->new({ test => $test,
	                                          parser => $parser,
	                                          formatter => $self,
	                           console_session => $console_session,
	                           verbosity => $self->verbosity});

	push @{ $self->sessions }, $session;

	return $session;
}


sub summary {
	my ($self, $agg) = @_;

	# normal console report
	$self->console->summary($agg);

	my $r = {
	     tests => [],
	     start_time => '?',
	     end_time => '?',
	     elapsed_time => $agg->elapsed_timestr,
	};

	for my $key (qw(total has_errors has_problems failed parse_errors passed
	             skipped todo todo_passed wait exit))
	{
		$r->{$key} = $agg->$key;
	}

	$r->{num_files} = scalar @{ $self->sessions };

	my $total_time = 0;
	foreach my $s (@{ $self->sessions }) {
		my $sr = $s->session_report;
		push @{$r->{tests}}, $sr;
		$total_time += $sr->{elapsed_time} || 0;
	}
	$r->{total_time} = $total_time;

	my $out = create_report($r, $self->verbosity);

	my $j = JSON->new->canonical(1);
	my $res = $j->pretty->utf8->encode($out);

	print { $self->output_fh } ${ \$res };
	close($self->output_fh);

	return $self;
}


sub _output {
	my $self = shift;
	$self->console->_output(@_);
}


sub create_report {
	my ($r, $verbosity) = @_;

	my %res = ();

	my $env = collect_run_env();

	$res{'run_env'} = $env;

	# status

	if ($r->{has_errors}) {
		$res{status} = 'failed';

	} else {
		$res{status} = 'passed';
	}

	$res{exit_status} = $r->{exit};
	$res{wait_status} = $r->{wait};

	# counters

	$res{parse_errors} = $r->{parse_errors};

	$res{tc_total} = $r->{total} + $r->{skipped};
	$res{tc_passed} = $r->{passed};
	$res{tc_failed} = $r->{failed};
	$res{tc_skipped} = $r->{skipped};
	$res{tc_todo} = $r->{todo};
	$res{tc_todo_passed} = $r->{todo_passed};

	# execution time

	$res{elapsed} = $r->{elapsed_time};
	$res{total_time} = $r->{total_time};

	my $files_passed = 0;
	my $files_failed = 0;
	my $files_skipped = 0;

	my %tests = ();

	for my $test (@{$r->{tests}}) {
		my %tres = ();
		my $tname = ($test->{test_base});

		if ($test->{skip_all}) {
			$files_skipped++;
		} elsif ($test->{test_status} eq 'passed' && $test->{tests_run} > 0) {
			$files_passed++;
		} else {
			$files_failed++;
		}

		$tres{exit_status} = $test->{exit};
		$tres{wait_status} = $test->{wait};
		$tres{status} = $test->{test_status};
		$tres{todo_passed} = $test->{todo_passed};
		$tres{problems} = $test->{has_problems};
		$tres{parse_errors} = $test->{num_parse_errors};
		$tres{skip_all} = $test->{skip_all};
		$tres{planned} = $test->{tests_planned};

		$tres{run} = $test->{tests_run};
		$tres{passed} = $test->{passed};
		$tres{failed} = $test->{failed};
		$tres{todo} = $test->{todo};
		$tres{skipped} = $test->{skipped};
		$tres{elapsed} = $test->{elapsed_time};
		$tres{started_at} = $test->{started_at};
		$tres{time_wall} = $test->{time_wall};
		$tres{time_user} = $test->{time_user};
		$tres{time_user_child} = $test->{time_user_child};
		$tres{time_user_total} = $test->{time_user_total};
		$tres{time_system} = $test->{time_system};
		$tres{time_system_child} = $test->{time_system_child};
		$tres{time_system_total} = $test->{time_system_total};
		$tres{time_process} = $test->{time_process};

		if ($verbosity > 0) {
			my @stdout;
			my @stderr;

			for my $line (@{$test->{xresults}}) {
				push @stdout, $line->{raw};
			}

			for my $line (@{$test->{err_lines}}) {
				push @stderr, $line;
			}

			$tres{stdout} = \@stdout;
			if (scalar @stderr) {
				$tres{stderr} = \@stderr;
			}
		}

		$tres{failed_tests} = $test->{failed_tests};

		if ($verbosity > -1) {
			my %stderr = ();

			for my $tnum (keys %{$test->{tc_errors}}) {

				my @tc_stderr;
				for my $line (@{$test->{tc_errors}{$tnum}}) {
					push @tc_stderr, $line;
				}

				$stderr{$tnum} = \@tc_stderr;
			}

			if (scalar keys %stderr) {
				$tres{tc_stderr} = \%stderr;
			}

			my %misc= ();

			for my $tnum (keys %{$test->{tc_misc}}) {

				my @tc_misc;
				for my $line (@{$test->{tc_misc}{$tnum}}) {
					push @tc_misc, $line;
				}

				$misc{$tnum} = \@tc_misc;
			}

			if (scalar keys %misc) {
				$tres{tc_misc} = \%misc;
			}

			my @tc_elapsed = ();

			my $prev = $test->{started_at};

			for my $end (@{$test->{tc_end_time}}) {
				push @tc_elapsed, $end - $prev;
				$prev = $end;
			}

			$tres{tc_elapsed} = \@tc_elapsed;
		}

		$tests{$tname} = \%tres;
	}

	$res{files_total} = $r->{num_files};
	$res{files_passed} = $files_passed;
	$res{files_failed} = $files_failed;
	$res{files_skipped} = $files_skipped;

	$res{tests} = \%tests;

	return \%res;
}


sub collect_run_env {

	my %info = ();

	my %env = ();

	# environment variables affecting us
	my @vars = (qw /TEST_ANGIE_BINARY TEST_ANGIE_VALGRIND TEST_ANGIE_CATLOG
	            TEST_ANGIE_VERBOSE TEST_ANGIE_UNSAFE TEST_ANGIE_TC
	            TEST_ANGIE_GLOBALS TEST_ANGIE_GLOBALS_HTTP
	            TEST_ANGIE_GLOBALS_STREAM TEST_ANGIE_DOCKER_REGISTRY
	            TEST_ANGIE_JOBS \
	            ASAN_OPTIONS CFLAGS CXXFLAGS LDFLAGS SHELL USER PATH/);

	foreach my $var (@vars) {
		$env{$var} = $ENV{$var};
	}

	$info{env} = \%env;

	# selected binary to run
	my $NGINX = defined $ENV{TEST_ANGIE_BINARY} ? $ENV{TEST_ANGIE_BINARY}
	: '../objs/angie';
	$info{binary} = $NGINX;

	# where we are?
	$info{cwd} = getcwd;

	# who we are?
	$info{uid} = $<;

	# our limits
	my @limits = split /\n/, `sh -c "ulimit -a" 2>&1`;
	$info{ulimit} = \@limits;

	# free memory
	# TODO: add something that works on BSD
	my @mem = split /\n/, `free -m 2>&1`;
	$info{freemem} = \@mem;

	# all the information the binary can give us
	my $vversion = `$NGINX -V 2>&1`;
	my @lines =  split /\n/,  $vversion;
	$info{verbose_version} = \@lines;

	# compiled in modules
	my $am = `$NGINX -m 2>&1`;
	my @modules = split /\n/,  $am;
	$info{modules} = \@modules;

	# final binary configuration
	my %be = ();
	my $lines = `$NGINX --build-env 2>&1`;
	my @build_env =  split /\n/,  $lines;
	for my $line (@build_env) {
		my ($item, $value) = $line =~  /^(\w+)\s*:\s+(.*)$/;
		$be{$item} = $value;
	}

	$info{build_env} = \%be;

	return \%info;
}

1;

