#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx ssi module, waited subrequests.

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

my $t = Test::Nginx->new()->has(qw/http ssi/)->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

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
            ssi on;
        }
    }
}

EOF

$t->write_file('index.html', 'x<!--#include virtual="/first.html" -->' .
	'x<!--#include virtual="/second.html" -->x');
$t->write_file('first.html', 'FIRST');
$t->write_file('second.html',
	'<!--#include virtual="/waited.html" wait="yes"-->xSECOND');
$t->write_file('waited.html', 'WAITED');

$t->run();

###############################################################################

{
local $TODO = 'broken in 0.7.25, patch under review';

like(http_get('/'), qr/^xFIRSTxWAITEDxSECONDx$/m, 'waited non-active');

}

like(`grep -F '[alert]' ${\($t->testdir())}/error.log`, qr/^$/s, 'no alerts');

###############################################################################
