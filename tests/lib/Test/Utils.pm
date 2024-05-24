package Test::Utils;

# (C) 2024 Web Server LLC

# Miscellaneous utils for testing

###############################################################################

use warnings;
use strict;

use parent qw/ Exporter /;
use Test::More;
use Test::Nginx qw/ http http_get /;

eval { require JSON; };
plan(skip_all => "JSON is not installed") if $@;

our @EXPORT_OK = qw/ get_json put_json delete_json patch_json /;

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

1;
