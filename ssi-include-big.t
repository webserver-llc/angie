#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx ssi bug with big includes.

###############################################################################

use warnings;
use strict;

use Test::More tests => 3;

use _common;
use Compress::Zlib;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

start_nginx('ssi-include-big.conf');

write_file('c1.html', 'X' x 1023);
write_file('c2.html', 'X' x 1024);
write_file('c3.html', 'X' x 1025);
write_file('test1.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c1.html" -->');
write_file('test2.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c2.html" -->');
write_file('test3.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c3.html" -->');

###############################################################################

my $t1 = http_gzip_request('/test1.html');
like($t1, qr/X{1023}/, 'small included file (less than output_buffers)');

my $t2 = http_gzip_request('/test2.html');
like($t2, qr/X{1024}/, 'small included file (equal to output_buffers)');

my $t3 = http_gzip_request('/test3.html');
like($t3, qr/X{1025}/, 'big included file (more than output_buffers)');

###############################################################################

sub http_gzip_request {
	my ($url) = @_;
	return `GET -t 1 -H 'Accept-Encoding: gzip' http://localhost:8080$url | gunzip -c`;
=pod

	my $r = http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Connection: close
Accept-Encoding: gzip

EOF
	return undef unless defined $r;
	return undef unless $r =~ m/\x0d\x0a\x0d\x0a(.*)/ms;
	return Compress::Zlib::memGunzip(my $b = $1);
=cut
}

sub write_file {
	my ($name, $content) = @_;

	open F, '>' . $_common::testdir . '/' . $name
		or die "Can't create $name: $!";
	print F $content;
	close F;
}

###############################################################################
