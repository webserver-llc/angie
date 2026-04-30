#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for "start" event posts and the immediately following "die" event.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################
#
select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api upstream_zone docker proxy rewrite/);

$t->skip_errors_check('alert',
	'cannot find Docker peer "" in http upstream "u"');

$t->write_file_expand('nginx.conf', <<"EOF");


%%TEST_GLOBALS%%

daemon off;

events {
}

error_log %%TESTDIR%%/error.log notice;

http {
    %%TEST_GLOBALS_HTTP%%

    docker_endpoint http://127.0.0.1:%%PORT_8081%%;

    upstream u {
        zone z 1m;
    }

    server {
        listen %%PORT_8080%%;

        location /api/ {
            api /;
        }
    }

    server {
        listen %%PORT_8081%%;

        default_type application/json;

        location /version {
            return 200 '{"ApiVersion":"1.47","MinAPIVersion":"1.24",
                        "Version":"28.0.0"}';
        }

        location ~ "^/v[0-9.]+/containers/json" {
            return 200 '[]';
        }

        location ~ "^/v[0-9.]+/events" {
            root %%TESTDIR%%;
            try_files /events.json =404;
        }
    }
}
EOF

my $cid = '3e72295424dd435aebe7ef5dd06bfe6162ac3ac487abe2cbd570583dc66dc706';

# Two consecutive events delivered in a single response body
$t->write_file('events.json',
	'{"status":"start","id":"' . $cid . '","from":"angie:latest",'
	. '"Type":"container","Action":"start",'
	. '"Actor":{"ID":"' . $cid . '",'
	. '"Attributes":{"angie.http.upstreams.u.port":"80"}},'
	. '"scope":"local","time":1734094746,"timeNano":1734094746965037092}'
	. "\n"
	. '{"status":"die","id":"' . $cid . '","from":"angie:latest",'
	. '"Type":"container","Action":"die",'
	. '"Actor":{"ID":"' . $cid . '",'
	. '"Attributes":{"angie.http.upstreams.u.port":"80"}},'
	. '"scope":"local","time":1734094747,"timeNano":1734094747965037092}'
	. "\n"
);

$t->run()->plan(2);

###############################################################################

# Wait for Docker module startup sequence to complete (conservative 2s)
select undef, undef, undef, 2.0;

is($t->find_in_file('error.log', qr/exited on signal/), 0,
	'worker process survived the "start" and "die" event sequence');

my $peers = get_json('/api/status/http/upstreams/u/peers');

is(scalar(keys %{$peers // {}}), 0,
	'no stale peers remain in upstream u after "start" and "die"');

###############################################################################
