#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx ssi bug with big includes.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has('rewrite')->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
    worker_connections  1024;
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    output_buffers  2 512;
    ssi on;
    gzip on;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /proxy/ {
            proxy_pass http://127.0.0.1:8080/local/;
        }
        location = /local/blah {
            return 204;
        }
    }
}

EOF

$t->write_file('c1.html', 'X' x 1023);
$t->write_file('c2.html', 'X' x 1024);
$t->write_file('c3.html', 'X' x 1025);
$t->write_file('test1.html', '<!--#include virtual="/proxy/blah" -->'
	. '<!--#include virtual="/c1.html" -->');
$t->write_file('test2.html', '<!--#include virtual="/proxy/blah" -->'
	. '<!--#include virtual="/c2.html" -->');
$t->write_file('test3.html', '<!--#include virtual="/proxy/blah" -->'
	. '<!--#include virtual="/c3.html" -->');
$t->write_file('test4.html', '<!--#include virtual="/proxy/blah" -->'
	. ('X' x 1025));

$t->run();

###############################################################################

my $t1 = http_gzip_request('/test1.html');
ok(defined $t1, 'small included file (less than output_buffers)');
http_gzip_like($t1, qr/^X{1023}\Z/, 'small included file content');

my $t2 = http_gzip_request('/test2.html');
ok(defined $t2, 'small included file (equal to output_buffers)');
http_gzip_like($t2, qr/^X{1024}\Z/, 'small included file content');

TODO: {
local $TODO = 'not fixed yet, patch under review';

my $t3 = http_gzip_request('/test3.html');
ok(defined $t3, 'big included file (more than output_buffers)');
http_gzip_like($t3, qr/^X{1025}\Z/, 'big included file content');

}

my $t4 = http_gzip_request('/test4.html');
ok(defined $t4, 'big ssi main file');
http_gzip_like($t4, qr/^X{1025}\Z/, 'big ssi main file content');


###############################################################################

sub http_gzip_request {
	my ($url) = @_;
	my $r = http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
Accept-Encoding: gzip

EOF
}

sub http_content {
	my ($text) = @_;

	return undef if !defined $text;

	if ($text !~ /(.*?)\x0d\x0a?\x0d\x0a?(.*)/ms) {
		return undef;
	}

	my ($headers, $body) = ($1, $2);

	if ($headers !~ /Transfer-Encoding: chunked/i) {
		return $body;
	}

	my $content = '';
	while ($body =~ /\G\x0d?\x0a?([0-9a-f]+)\x0d\x0a?/gcmsi) {
		my $len = hex($1);
		$content .= substr($body, pos($body), $len);
		pos($body) += $len;
	}

	return $content;
}

sub http_gzip_like {
	my ($text, $re, $name) = @_;

	SKIP: {
		eval { require IO::Uncompress::Gunzip; };
		skip "IO::Uncompress::Gunzip not installed", 1 if $@;

		my $in = http_content($text);
		my $out;

		IO::Uncompress::Gunzip::gunzip(\$in => \$out);

		like($out, $re, $name);
	}
}

###############################################################################
