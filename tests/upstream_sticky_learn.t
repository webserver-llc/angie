#!/usr/bin/perl

# (C) 2022 Web Server LLC

# Tests for upstream module with sticky learn feature.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/annotate/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->has(qw/http_ssl proxy rewrite upstream_sticky/)
	->has_daemon('openssl')
	->plan(81)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format stk '$remote_addr - $remote_user [$time_local]'
                   ' "$request" $status $body_bytes_sent us=[$upstream_status]'
                   ' ss=[$upstream_sticky_status]';

    access_log sticky_acess.log stk;

    # direct access to all backends for test harness
    #
    # backend_1...5  HTTP backends with sticky cookie

    upstream backend_1 {
        server 127.0.0.1:%%PORT_8081%%;
        sticky cookie sticky;
    }

    upstream backend_2 {
        server 127.0.0.1:%%PORT_8082%%;
        sticky cookie sticky;
    }

    upstream backend_3 {
        server 127.0.0.1:%%PORT_8083%%;
        sticky cookie sticky;
    }

    upstream backend_4 {
        server 127.0.0.1:%%PORT_8084%%;
        sticky cookie sticky;
    }

    upstream backend_5 {
        server 127.0.0.1:%%PORT_8085%%;
        sticky cookie sticky;
    }

    # Upstreams for test cases: 1 upstream per testcase

    upstream tc_1 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn
                     zone=z1:1m;
    }

    upstream tc_1secret {
        server 127.0.0.1:%%PORT_8081%% sid=x1;
        server 127.0.0.1:%%PORT_8082%% sid=x2;
        server 127.0.0.1:%%PORT_8083%% sid=x3;
        server 127.0.0.1:%%PORT_8084%% sid=x4;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn
                     zone=z1secret:1m;
        sticky_secret hidden$arg_secret;
    }

    upstream tc_2 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn header
                     zone=z2:1m;
    }

    upstream tc_3 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn header
                     zone=z3:1m timeout=2s;
    }

    upstream tc_4 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_request_id
                     zone=z4:128k;
    }

    upstream tc_5 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn
                     zone=z5:1m;
    }

    upstream tc_6 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn lookup=$arg_larg
                     create=$upstream_http_x_learn
                     zone=z6:1m;
    }

    upstream tc_7 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn
                     lookup=$arg_a                         # not set
                     lookup=$arg_b                         # not set
                     lookup=$arg_c                         # not set
                     lookup=$arg_larg                      # used
                     create=$arg_x                         # not set
                     create=$upstream_http_x_learn header  # used
                     zone=z7:1m;
    }

    # missing vars, N lookup > N create
    upstream tc_8a {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn
                     lookup=$arg_a                         # not set
                     lookup=$arg_b                         # not set
                     lookup=$arg_c                         # not set
                     lookup=$arg_d                         # not set
                     lookup=$arg_e                         # not set
                     lookup=$arg_f                         # not set
                     lookup=$arg_g                         # not set
                     create=$arg_x                         # not set
                     zone=z8a:1m;
    }

    # missing vars, N create > N lookup
    upstream tc_8b {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        sticky learn
                     lookup=$arg_larg
                     create=$arg_a                         # not set
                     create=$arg_b                         # not set
                     create=$arg_c                         # not set
                     create=$upstream_http_x_learn header
                     zone=z8b:1m;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;

        # Entry points for test harness

        location /backend_1 { proxy_pass http://backend_1/; }
        location /backend_2 { proxy_pass http://backend_2/; }
        location /backend_3 { proxy_pass http://backend_3/; }
        location /backend_4 { proxy_pass http://backend_4/; }
        location /backend_5 { proxy_pass http://backend_5/; }

        # Entry points for corresponding test cases

        location /tc_1 {
            proxy_pass http://tc_1/;
        }

        location /tc_1secret {
            proxy_pass http://tc_1secret/;
        }

        location /tc_2 {
            proxy_pass http://tc_2/;
        }

        location /tc_3 {
            proxy_pass http://tc_3/;
        }

        location /tc_4 {
            proxy_pass http://tc_4/;
        }

        location /tc_5 {
            proxy_pass http://tc_5/;
        }

        location /tc_6 {
            proxy_pass http://tc_6/;
            proxy_next_upstream http_503;
        }

        location /tc_7 {
            proxy_pass http://tc_7/;
        }

        location /tc_8a {
            proxy_pass http://tc_8a/;
        }

        location /tc_8b {
            proxy_pass http://tc_8b/;
        }

    }

    # Backends used in tests

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        listen       127.0.0.1:%%PORT_9081%% ssl;
        location / {
            add_header X-Backend B1;
            add_header X-Learn a;
            add_header X-Request-Id $request_id;
            return 200 B1;
        }

        location /nolearn {
            add_header X-Backend B1;
            return 200 B1;
        }

        location /bad {
            add_header X-Backend B1;
            return 503;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8082%%;
        listen       127.0.0.1:%%PORT_9082%% ssl;
        location / {
            add_header X-Backend B2;
            add_header X-Learn bb;
            add_header X-Request-Id $request_id;
            return 200 B2;
        }
        location /nolearn {
            add_header X-Backend B2;
            add_header X-Request-Id $request_id;
            return 200 B2;
        }

        location /bad {
            add_header X-Backend B2;
            return 503;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8083%%;
        listen       127.0.0.1:%%PORT_9083%% ssl;
        location / {
            add_header X-Backend B3;
            add_header X-Learn ccc;
            return 200 B3;
        }

        location /nolearn {
            add_header X-Backend B3;
            return 200 B3;
        }

    }

    server {
        listen       127.0.0.1:%%PORT_8084%%;
        listen       127.0.0.1:%%PORT_9084%% ssl;
        location / {
            add_header X-Backend B4;
            add_header X-Learn dddd;
            return 200 B4;
        }

        location /nolearn {
            add_header X-Backend B4;
            return 200 B4;
        }

    }

    # "broken" by default backend
    server {
        listen       127.0.0.1:%%PORT_8085%%;
        listen       127.0.0.1:%%PORT_9085%% ssl;
        location / {
            add_header X-Backend B5;
            return 502;
        }

        location /good {
            add_header X-Backend B5;
            return 200 B5;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();

# wait for all backends to be available
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8083));
$t->waitforsocket('127.0.0.1:' . port(8084));
$t->waitforsocket('127.0.0.1:' . port(8085));

# wait for all backends to be available
$t->waitforsocket('127.0.0.1:' . port(9081));
$t->waitforsocket('127.0.0.1:' . port(9082));
$t->waitforsocket('127.0.0.1:' . port(9083));
$t->waitforsocket('127.0.0.1:' . port(9084));
$t->waitforsocket('127.0.0.1:' . port(9085));

###############################################################################

my %learn_map = (
	B1 => 'a',
	B2 => 'bb',
	B3 => 'ccc',
	B4 => 'dddd',
);

###############################################################################

tc1('Sticky learn');
tc1secret('Sticky learn with secret');
tc2('Sticky learn header');
tc3('Sticky learn timeout');
tc4('Sticky learn fill zone');
tc6('Sticky learn sessions from lookup');
tc7('Sticky learn multiple variables');
tc8('Sticky learn no variables');

# the reload test must be the last
SKIP: {
	skip 'reload is not working (perl >= 5.32 required)', 13
		unless $t->has_feature('reload');

	tc5('Sticky learn preserved on reload', $t);
}

###############################################################################

# verify sticky learn
sub tc1 {
	annotate(@_);

	verify_rr('/tc_1', 4, 4);
	verify_learn_upstream('/tc_1', \%learn_map);
}

# verify sticky learn with secret
sub tc1secret {
	annotate(@_);

	verify_rr('/tc_1secret', 4, 4);
	verify_learn_upstream('/tc_1secret', \%learn_map, 'bar');
}

# verify sticky learn + header
sub tc2 {
	annotate(@_);
	verify_learn_upstream('/tc_2', \%learn_map);
}

# verify sticky learn + timeout
sub tc3 {
	annotate(@_);

	verify_learn_upstream('/tc_3', \%learn_map);

	# sessions created, let them expire
	select undef, undef, undef, 3;

	# we expect RR to select first available backend, i.e. B1
	my %reply = get_sticky_reply('/tc_3?larg=B4');
	my $sn = $reply{learn};
	is($reply{backend}, 'B1', "learn: B4 session expired, learn id:'$sn'");
}

# verify sticky learn fill zone - for coverage
sub tc4 {
	annotate(@_);

	my $fail = 0;

	# each backend response generates new sesion
	# make a bunch of requests to fill in the zone
	for (1 .. 1024) {
		my %reply = get_sticky_reply('/tc_4');
		if (!defined $reply{backend}) {
			$fail = 1;
		}
	}
	isnt($fail, 1, 'No issues with filled zone');
}

# verify sticky learn + reload
sub tc5 {
	annotate(@_);

	my ($name, $t) = @_;

	verify_learn_upstream('/tc_5', \%learn_map);
	# sessions created, reload and test

	ok($t->reload(), 'reloaded');

	verify_sticky_learn('/tc_5', $learn_map{B2}, 'B2');
	verify_sticky_learn('/tc_5', $learn_map{B1}, 'B1');
	verify_sticky_learn('/tc_5', $learn_map{B4}, 'B4');
	verify_sticky_learn('/tc_5', $learn_map{B3}, 'B3');
}

# verify sticky learn sessions from lookup
sub tc6 {
	annotate(@_);

	# create sessions
	verify_learn_upstream('/tc_6', \%learn_map);

	# request to backend that does not create sessions - session to be updated
	my %reply = get_sticky_reply('/tc_6/nolearn?larg=' . $learn_map{B4});

	# ensure we still hit B4
	verify_sticky_learn('/tc_6', $learn_map{B4}, $reply{backend});

	# coverage tests below

	# RR selects backend: no create variables
	%reply = get_sticky_reply('/tc_6/nolearn');

	# 1) we have session for B2
	# 2) make B2 FAIL (/bad returns 503)
	# 3) another backend is selected
	%reply = get_sticky_reply('/tc_6/bad?larg=' . $learn_map{B2});

	# 4) now request B2 with old session key
	# 5) session is found, but attached to another backend
	%reply = get_sticky_reply('/tc_6/nolearn?larg=' . $learn_map{B2});
}

# same as tc2 but with multiple variables
sub tc7 {
	annotate(@_);
	verify_learn_upstream('/tc_7', \%learn_map);
}

# variables are missing
sub tc8 {
	annotate(@_);

	my %res = get_sticky_reply('/tc_8a');

	is($res{code}, 200, 'got response from some backend');

	verify_learn_upstream('/tc_8b', \%learn_map);
}

###############################################################################

# makes an HTTP request to passed $uri
# returns hash with various response properties: backend, code
sub get_sticky_reply {
	my ($uri) = @_;

	my $response = http_get($uri);

	my ($backend) = $response =~ /X-Backend: (B\d+)/;
	my ($learn)   = $response =~ /X-Learn: (\w+)/;
	my ($code)    = $response =~ qr!HTTP/1.1 (\d\d\d)!ms;

	my %result = (
		backend => $backend,
		learn   => $learn,
		code    => $code
	);

	return %result;
}

###############################################################################

# verify that backends in upstream are sticked via learn
sub verify_learn_upstream {
	my ($uri, $bmap, $secret) = @_;

	my $sarg = (defined $secret) ? "?secret=$secret" : '';

	my %reply = get_sticky_reply("$uri$sarg");
	my $sn = $reply{learn};
	is($reply{backend}, 'B1', "Learning B1: session name: $sn at $uri");

	%reply = get_sticky_reply("$uri$sarg");
	$sn = $reply{learn};
	is($reply{backend}, 'B2', "Learning B2: session name: $sn at $uri");

	%reply = get_sticky_reply("$uri$sarg");
	$sn = $reply{learn};
	is($reply{backend}, 'B3', "Learning B3: session name: $sn at $uri");

	%reply = get_sticky_reply("$uri$sarg");
	$sn = $reply{learn};
	is($reply{backend}, 'B4', "Learning B4: session name: $sn at $uri");

	verify_sticky_learn($uri, $bmap->{B2}, 'B2', $secret);
	verify_sticky_learn($uri, $bmap->{B1}, 'B1', $secret);
	verify_sticky_learn($uri, $bmap->{B3}, 'B3', $secret);
	verify_sticky_learn($uri, $bmap->{B4}, 'B4', $secret);
}

# perform: send request to $uri 4 times with route for $backend
# verify:  same backend is returned all times
sub verify_sticky_learn {
	my ($uri, $route, $backend, $secret) = @_;

	my $n = 4;
	my $actual = '';

	$secret = (defined $secret) ? "&secret=$secret" : '';

	for (1 .. $n) {
		my %res = get_sticky_reply("$uri?larg=$route$secret");
		$actual .= $res{"backend"};
	}

	is($actual, $backend x $n, "request to $uri and backend $backend is sticky");
}

# increment key in hash or create new key
sub inckey {
	my ($hash, $key) = @_;

	$hash->{$key} //= 0;
	$hash->{$key} ++;
}

# perform $n x $nb requests (assuming $nb backends)
# expect equal number of responses ($n) from each backend
sub verify_rr {
	my ($uri, $nb, $n) = @_;

	my %distr;

	my $total = $nb * $n;

	for (1 .. $total) {
		my %reply = get_sticky_reply($uri);

		inckey(\%distr, $reply{backend});
	}

	for (1 .. $nb) {
		is ($distr{"B$_"}, $n, "RR check: backend B$_ got $n/$total requests");
	}
}
