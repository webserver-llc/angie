#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for autoindex module.

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

my $t = Test::Nginx->new()->has(qw/http autoindex/)->plan(4)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

master_process off;
daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            autoindex on;
        }
    }
}

EOF

my $d = $t->testdir();

mkdir("$d/test-dir");
symlink("$d/test-dir", "$d/test-dir-link");

$t->write_file('test-file', '');
symlink("$d/test-file", "$d/test-file-link");

$t->run();

###############################################################################

my $r = http_get('/');

like($r, qr!href="test-file"!ms, 'file');
like($r, qr!href="test-file-link"!ms, 'symlink to file');
like($r, qr!href="test-dir/"!ms, 'directory');
like($r, qr!href="test-dir-link/"!ms, 'symlink to directory');

###############################################################################
