#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for prometheus export module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/:DEFAULT http_post/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_api prometheus rewrite/)->plan(18);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    prometheus_template test_template {
        angie_connections_accepted $p8s_value
            path=/connections/accepted
            type=counter
            'help=Total accepted connections';

        angie_connections_active $p8s_value
            path=/connections/active
            type=gauge
            'help=Active connections';

        'angie_http_server_zones_requests{zone="$1"}' $p8s_value
            path=~^/http/server_zones/([^/]+)/requests/total$
            type=counter
            'help=Total requests in server zone';

        'angie_http_server_zones_responses{zone="$1",code="$2"}' $p8s_value
            path=~^/http/server_zones/([^/]+)/responses/([^/]+)$
            type=counter
            'help=Response codes in server zone';
    }

    server {
        server_name localhost;
        listen 127.0.0.1:8080;

        status_zone test_zone;

        location /metrics {
            prometheus test_template;
        }

        location /ok {
            return 200 OK;
        }
    }
}

EOF

$t->run();

###############################################################################

# Generate some traffic to create metrics
http_get('/');   # 403
http_get('/ok'); # 200

# Test basic Prometheus endpoint
my $metrics = http_get('/metrics');

like($metrics, qr/200 OK/, 'prometheus endpoint returns 200');
like($metrics, qr/Content-Type: text\/plain/, 'correct content type');
like($metrics, qr/Cache-Control: no-cache/, 'no-cache header set');

# Test template comment
like($metrics, qr/^# Angie Prometheus template "test_template"$/m,
	'template name in output');

# Test HELP and TYPE lines
like($metrics,
	qr/^# HELP angie_connections_accepted Total accepted connections$/m,
	'angie_connections_accepted: help text present');
like($metrics, qr/^# TYPE angie_connections_accepted counter$/m,
	'angie_connections_accepted: type declaration present');
like($metrics, qr/^# HELP angie_connections_active Active connections$/m,
	'angie_connections_active: help text present');
like($metrics, qr/^# TYPE angie_connections_active gauge$/m,
	'angie_connections_active: type declaration present');
like($metrics, qr{^\#\s HELP\s angie_http_server_zones_requests\s
	Total\s requests\s in\s server\s zone$}mx,
	'angie_http_server_zones_requests: help text present');
like($metrics, qr/^# TYPE angie_http_server_zones_requests counter$/m,
	'angie_http_server_zones_requests: type declaration present');
like($metrics, qr{^\#\s HELP\s angie_http_server_zones_responses\s
	Response\s codes\s in\s server\s zone$}mx,
	'angie_http_server_zones_responses: help text present');
like($metrics, qr/^# TYPE angie_http_server_zones_responses counter$/m,
	'angie_http_server_zones_responses: type declaration present');

# Test metric values
like($metrics, qr/^angie_connections_accepted 3$/m,
	'connections accepted metric');
like($metrics, qr/^angie_connections_active 1$/m,
	'connections active metric');

# Test metrics with labels
like($metrics, qr/^angie_http_server_zones_requests\{zone="test_zone"\} 3$/m,
	'server zone metric with label');
like($metrics,
	qr/^angie_http_server_zones_responses\{zone="test_zone",code="403"\} 1$/m,
	'response code metric with multiple labels, code 403');
like($metrics,
	qr/^angie_http_server_zones_responses\{zone="test_zone",code="200"\} 1$/m,
	'response code metric with multiple labels, code 200');

# Test method restrictions
like(http_post('/metrics'), qr/405 Method Not Allowed/,
	'POST method not allowed');

###############################################################################
