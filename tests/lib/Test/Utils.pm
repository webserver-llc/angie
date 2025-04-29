package Test::Utils;

# (C) 2024 Web Server LLC

# Miscellaneous utils for testing

###############################################################################

use warnings;
use strict;

use parent qw/ Exporter /;
use IO::Select;
use IO::Socket qw/ SHUT_WR TCP_MAXSEG TCP_NODELAY IPPROTO_TCP /;
use List::Util qw/ sum0 /;
use Test::More;

use Test::Nginx qw/ http http_get log_in log_out port /;

eval { require JSON; };
plan(skip_all => "JSON is not installed") if $@;

our @EXPORT_OK = qw/ get_json put_json delete_json patch_json annotate
	getconn hash_like stream_daemon trim /;

sub _parse_response {
	my $response = shift;

	my ($headers, $body) =  split /\n\r/, $response, 2;

	my $json;
	eval {
		# allows to accept scalars as valid JSON
		my $jobj = JSON->new->allow_nonref;
		$json = $jobj->decode($body);
	};
	if ($@) {
		undef $json;
	}

	return {h => $headers, j => $json};
}

sub get_json {
	my ($uri) = @_;

	my $res = _parse_response(http_get($uri));
	return $res->{j};
}

sub put_json {
	my ($uri, $jbody, $asis) = @_;
	return send_json('PUT', $uri, $jbody, $asis);
}

sub patch_json {
	my ($uri, $jbody, $asis) = @_;
	return send_json('PATCH', $uri, $jbody, $asis);
}

sub delete_json {
	my ($uri) = @_;

	my $response = http_delete($uri);
	return _parse_response($response);
}

sub send_json {
	my ($method, $uri, $jbody, $asis) = @_;

	my $payload;

	if ($asis) {
		$payload = $jbody;
	} else {
		# allows to accept scalars as valid JSON
		my $jobj = JSON->new->allow_nonref;
		$payload = $jobj->encode($jbody);
	}

	my $response = http_body($method, $uri, $payload);
	return _parse_response($response);
}

sub http_delete($;%) {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
DELETE $url HTTP/1.0
Host: localhost

EOF
}

sub http_body {
	my ($method, $url, $body, %extra) = @_;

	my $clen;
	{
		use bytes;
		$clen = length($body);
	}

	return http(<<EOF, %extra);
$method $url HTTP/1.0
Host: localhost
Content-Length: $clen

$body
EOF
}

sub annotate {
	my ($tc) = @_;

	my $tname = (split(/::/, (caller(1))[3]))[1];
	note("# ***  $tname: $tc \n");
}

# opens connection to a specified host and port
sub getconn {
	my ($host, $port) = @_;

	my $s = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerPort => $port // port(8080),
		PeerHost => $host // '127.0.0.1'
	)
		or die "Can't connect to nginx: $!\n";

	return $s;
}

# compares two hashes with some allowance
# for example, the following statement is considered true:
#	hash_like({a => 10, b => 5}, {a => 8, b => 7}, 2)
sub hash_like {
	my ($got, $expected, $allowance, $test_name) = @_;

	$allowance //= 0;

	my $got_total      = sum0 values %{ $got      // {} };
	my $expected_total = sum0 values %{ $expected // {} };

	my $pass = 0;

	if ($got_total == $expected_total) {

		$pass = 1;
		foreach my $key (keys %{$expected}) {
			if (abs(($got->{$key} // 0) - $expected->{$key}) > $allowance) {
				$pass = 0;
				last;
			}
		}
	}

	return 1
		if ok($pass == 1, "$test_name");

	diag(explain({
		test_name => $test_name, allowance => $allowance,
		got => $got, expected => $expected,
	}));
}

# reads response from socket until $trailing_char at the end of the input
sub socket_read {
	my ($s, %extra) = @_;

	my $data = '';
	$s->blocking(0);
	while (IO::Select->new($s)->can_read($extra{timeout} // 3)) {
		my $bytes_read = sysread($s, my $buffer, 4096);
		if (!defined $bytes_read) {
			diag("socket_read(): error while reading from socket: $!");
			last;
		}

		last if $bytes_read == 0;

		$data .= $buffer;

		if (defined $extra{trailing_char}) {
			last if $buffer =~ /\Q$extra{trailing_char}\E$/;
		}
	}

	log_in($data);
	return $data;
}

sub socket_write {
	my ($s, $message, %extra) = @_;

	local $SIG{PIPE} = 'IGNORE';

	$s->blocking(0);
	while (IO::Select->new($s)->can_write($extra{timeout} // 1.5)) {
		my $bytes_written = $s->syswrite($message);
		if (!defined $bytes_written) {
			note("socket_write(): error while writing to socket: $!");
			last;
		}

		last if $bytes_written == 0;

		log_out(substr($message, 0, $bytes_written));

		$message = substr($message, $bytes_written);
		last unless length $message;
	}

	if (length $message) {
		$s->close();
	}
}

sub stream_daemon {
	my $port   = shift;
	my $params = shift // {};

	my $server = IO::Socket::INET->new(
		Proto     => $params->{proto} // 'tcp',
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Listen    => 5,
		Reuse     => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	$server->setsockopt(IPPROTO_TCP, TCP_NODELAY, $params->{tcp_nodelay})
		if defined $params->{tcp_nodelay};

	$server->setsockopt(IPPROTO_TCP, TCP_MAXSEG, $params->{tcp_maxseg})
		if defined $params->{tcp_maxseg};

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $client_port = $client->sockport();
		log2c("(new connection to $client_port)");

		my $input = socket_read($client,
			trailing_char => $params->{trailing_char} // '$');
		log2i("|| << $client_port $input");

		my $output = $client->sockport();
		my $output_length = length $output;
		if (defined $params->{response_length}) {
			my $response_length = $params->{response_length};

			if ($response_length < $output_length) {
				die "response_length can't be less than $output_length"
					. " ($response_length requested, output = '$output')";
			}

			$output = $output x ($response_length / $output_length);
			if (length $output < $response_length) {
				$output .= '.' x ($response_length - length $output);
			}
		}
		log2o("|| >> $client_port $output");

		socket_write($client, $output);

		$client->shutdown(SHUT_WR);
		log2c("(connection to $client_port closed)")
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }

sub trim {
	my $string = shift;
	$string =~ s/^\s+|\s+$//g;
	return $string;
}

1;
