package Test::Nginx::Config;

# (C) 2024 Web Server LLC

# Module for nginx config.

###############################################################################

use warnings;
use strict;

our $THESAURUS = {
	order => [qw(globals pid error_log daemon worker_processes events stream
		http)],
	children => {
		globals => {
			hide_name => 1, delimiter => '',
			default_value => '%%TEST_GLOBALS%%'
		},
		events => {
			order => [qw(worker_connections)],
		},
		stream => {
			order => [qw(globals upstreams servers)],
			children => {
				globals => {hide_name => 1, delimiter => ''},
				upstreams => {
					singular => 'upstream',
					order => [qw(zone balancer response_time_factor servers)],
					children => {
						balancer => {hide_name => 1},
						servers  => {singular => 'server'},
					},
				},
				servers => {
					singular => 'server',
					order    => [qw(listen return proxy_pass)],
				},
			}
		},
		http => {
			order => [qw(globals servers)],
			children => {
				globals => {
					hide_name => 1, delimiter => '',
					default_value => '%%TEST_GLOBALS_HTTP%%'
				},
				servers => {
					singular => 'server',
					order    => [qw(listen location)],
					children => {
						location => {
							order => [qw(uri return)],
							children => {
								uri => {hide_name => 1},
							}
						}
					}
				},
			},
		},
	}
};

sub new {
	my ($class, $config) = @_;

	my $self = bless {}, $class;

	$self->{config} = {
		daemon           => 'off',
		worker_processes => '1',
		events           => {},
		%{$config // {}}, # TODO: smart merge
	};

	return $self;
}

# TODO this only works for one depth level
sub update {
	my ($self, $new_config) = @_;
	$self->{config} = { %{$self->{config}}, %$new_config };
}

sub add_element {
	my ($self, $element) = @_;

	while (my ($name, $elem) = each %$element) {
		$self->_add_child_to_hash($self->{config}, $name, $elem);
	}
}

sub _add_child_to_hash {
	my ($self, $parent, $child_name, $child) = @_;

	unless (defined $parent->{$child_name}) {
		$parent->{$child_name} = $child;
		return;
	}

	# TODO smart merge
	if (ref $child eq 'HASH') {
		for my $k (sort keys %$child) {
			my $v = $child->{$k};
			$self->_add_child_to_hash($parent->{$child_name}, $k, $v);
		}

	} elsif (ref $child eq 'ARRAY') {
		# TODO append if not defined
		push @{$parent->{$child_name}}, $child;

	} else {

	}

	return;
}

sub convert_to_string {
	my ($self) = @_;

	my $config_string = '';
	for my $child (@{$THESAURUS->{order}}) {
		$config_string .= append_child(
			$self->{config}{$child}, $child, $THESAURUS->{children}{$child}, ''
		);
	}

	return $config_string;
}

sub append_child {
	my ($config_section, $config_section_name, $thesaurus, $indent) = @_;

	$config_section //= $thesaurus->{default_value};

	return '' unless defined $config_section;

	$thesaurus //= {};

	my $config_string = '';

	if (ref $config_section eq 'HASH') {
		my $name = $config_section->{name} // '';

		$config_string .= "\n" . $indent . $config_section_name . " $name {\n";

		for my $child_name (@{$thesaurus->{order}}) {
			$config_string .= append_child(
				$config_section->{$child_name}, $child_name,
				$thesaurus->{children}{$child_name}, $indent . (' ' x 4)
			);
		}
		$config_string .= $indent . "}\n";

	} elsif (ref $config_section eq 'ARRAY') {
		for my $child (@{$config_section}) {
			$config_string .= append_child(
				$child, $thesaurus->{singular}, $thesaurus, $indent);
		}

	} else {
		my $delimiter =
			(defined $thesaurus->{delimiter}) ? $thesaurus->{delimiter} : ';';

		$config_string .= $indent
			. ($thesaurus->{hide_name} ? '' : $config_section_name . ' ' )
			. $config_section . $delimiter . "\n";
	}

	return $config_string;
}

1;
