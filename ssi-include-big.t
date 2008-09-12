#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx ssi bug with big includes.

###############################################################################

use warnings;
use strict;

use Test::More tests => 3;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->run('ssi-include-big.conf');

$t->write_file('c1.html', 'X' x 1023);
$t->write_file('c2.html', 'X' x 1024);
$t->write_file('c3.html', 'X' x 1025);
$t->write_file('test1.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c1.html" -->');
$t->write_file('test2.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c2.html" -->');
$t->write_file('test3.html', '<!--#include virtual="/proxy/blah" -->' . "\n"
	. '<!--#include virtual="/c3.html" -->');

###############################################################################

my $t1 = http_gzip_request('/test1.html');
ok(defined $t1, 'small included file (less than output_buffers)');

my $t2 = http_gzip_request('/test2.html');
ok(defined $t2, 'small included file (equal to output_buffers)');

my $t3 = http_gzip_request('/test3.html');
ok(defined $t3, 'big included file (more than output_buffers)');

###############################################################################

sub http_gzip_request {
	my ($url) = @_;
	my $r = http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Connection: close
Accept-Encoding: gzip

EOF
}

###############################################################################
