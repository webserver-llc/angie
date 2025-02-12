package Test::Nginx::Config;

# (C) 2024 Web Server LLC

# Module for nginx config.

# TODO indents between some elements, comments

###############################################################################

use warnings;
use strict;

use Test::More;

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
			order => [qw(globals upstream server)],
			children => {
				globals => {
					hide_name => 1, delimiter => '',
					default_value => '%%TEST_GLOBALS_STREAM%%',
				},
				upstream => {
					order => [qw(zone balancer response_time_factor server)],
					children => {
						balancer => {hide_name => 1},
					},
				},
				server => {
					order => [qw(listen return proxy_pass)],
				},
			}
		},
		http => {
			order => [qw(globals resolver upstream server)],
			children => {
				globals => {
					hide_name => 1, delimiter => '',
					default_value => '%%TEST_GLOBALS_HTTP%%'
				},
				upstream => {
					order => [qw(zone balancer server)],
					children => {
						balancer => {hide_name => 1},
					},
				},
				server => {
					order => [qw(listen server_name location add_header)],
					children => {
						location => {
							order => [qw(uri internal return proxy_pass)],
							children => {
								uri => {hide_name => 1},
							}
						},
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
		%{ $config // {} },
	};

	return $self;
}

sub update {
	my ($self, $new_config) = @_;
	$self->add($new_config, 1);
}

sub add_api_server {
	my $self = shift;

	$self->add_http_server(
		{
			listen => '127.0.0.1:8080',
			location => [{
				name => '/api/',
				uri  => 'api /',
			}],
		}
	);
}

sub add {
	my ($self, $elements, $rewrite) = @_;

	while (my ($name, $element) = each %{ $elements }) {
		$self->_add_child(
			config => $self->{config}, $name => $element, $rewrite);
	}
}

sub _add_child {
	my ($self, $parent_name, $parent, $child_name, $child, $rewrite) = @_;

	unless (defined $parent->{$child_name}) {
		$parent->{$child_name} = $child;
		return;
	}

	if (ref $child eq 'HASH') {
		while (my ($k, $v) = each %{ $child }) {
			$self->_add_child(
				$child_name => $parent->{$child_name}, $k => $v, $rewrite);
		}
	} elsif (ref $child eq 'ARRAY') {
		if ($parent_name eq 'http' && $child_name eq 'server') {
			$self->add_http_server($child, $parent);
		} else {
			if ($rewrite) {
				$parent->{$child_name} = $child;
			} else {
				push @{ $parent->{$child_name} }, @{ $child };
			}
		}
	} else {
		if ($rewrite) {
			$parent->{$child_name} = $child;
		} else {
			# ambiguity
			die "Can't add $child_name to $parent_name.\n"
				. "(old value: $parent->{$child_name}, new value: $child";
		}
	}

	return;
}

sub add_http_server {
	my ($self, $server, $parent) = @_;

	$self->{config}{http} //= {server => []};
	$parent //= $self->{config}{http}{server};

	if (ref $server eq 'ARRAY') {
		foreach my $elem (@{ $server }) {
			$self->add_http_server($elem);
		}
		return;
	}

	push @{ $parent }, $server;
}

sub convert_to_string {
	my ($self) = @_;

	my $config_string = '';
	for my $child (@{ $THESAURUS->{order} }) {
		$config_string .= append_child(
			$self->{config}{$child}, $child, $THESAURUS->{children}{$child}, ''
		);
	}

	return $config_string;
}

sub append_child {
	my ($config_section, $config_section_name, $thesaurus, $indent, $inline) = @_;

	$config_section //= $thesaurus->{default_value};

	return '' unless defined $config_section;

	$config_section =~ s/\s+$//; # remove trailing spaces

	$thesaurus //= {};

	my $config_string = '';

	$inline = $inline // $thesaurus->{inline} // 0;

	if (ref $config_section eq 'HASH') {
		if ($inline) {
			$config_string .= $indent . $config_section_name;
			for my $child_name (@{ $thesaurus->{order} }) {
				$config_string .= append_child(
					$config_section->{$child_name}, $child_name,
					$thesaurus->{children}{$child_name}, ' ', 1
				);
			}
			$config_string .= ";\n";

		} else {

			my $name = $config_section->{name} // '';

			$config_string .= "\n" . $indent . $config_section_name
				. " $name {\n";

			if (defined $config_section->{_as_is}) {
				$config_string .= $config_section->{_as_is};
			}

			for my $child_name (@{ $thesaurus->{order} }) {
				$config_string .= append_child(
					$config_section->{$child_name}, $child_name,
					$thesaurus->{children}{$child_name}, $indent . (' ' x 4)
				);
			}
			$config_string .= $indent . "}\n";
		}

	} elsif (ref $config_section eq 'ARRAY') {
		for my $child (@{ $config_section }) {
			$config_string .= append_child($child,
				$config_section_name,
				$thesaurus, $indent, $inline
			);
		}

	} else {
		my $hide_name = $thesaurus->{hide_name};

		if ($thesaurus->{boolean}) {
			return '' unless $config_section;

			$hide_name = 1;
			$config_section = $config_section_name;
		}

		my $delimiter = (defined $thesaurus->{delimiter})
			? $thesaurus->{delimiter}
			: ($inline ? '' : ';');

		$config_string .= $indent
			. ($hide_name ? '' : $config_section_name)
			. ($thesaurus->{use_equal_sign} ? '=' : ($hide_name ? '' : ' '))
			. $config_section . $delimiter . ($inline ? '' : "\n");
	}

	return $config_string;
}

1;
