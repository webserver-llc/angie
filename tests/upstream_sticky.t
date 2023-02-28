#!/usr/bin/perl

# (C) 2022 Web Server LLC

# Tests for upstream module with sticky feature.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $debug = 1; # set to 1 to enable

my $t = Test::Nginx->new()->has(qw/http ssl proxy rewrite upstream_least_conn/)
	->has(qw/upstream_ip_hash upstream_hash upstream_random/)
	->has(qw/upstream_sticky/)->plan(109);

$t->write_file_expand('nginx.conf', <<'EOF');

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
    # sbackend_1...5 HTTP backends with sticky cookie + secret
    # rbackend_1...5 HTTP backends with sticky route
    # sslbackend_1..5 HTTPS backends with sticky cookie

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

    upstream sbackend_1 {
        server 127.0.0.1:%%PORT_8081%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream sbackend_2 {
        server 127.0.0.1:%%PORT_8082%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream sbackend_3 {
        server 127.0.0.1:%%PORT_8083%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream sbackend_4 {
        server 127.0.0.1:%%PORT_8084%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream sbackend_5 {
        server 127.0.0.1:%%PORT_8085%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream rbackend_1 {
        server 127.0.0.1:%%PORT_8081%% sid=a;
        sticky cookie sticky;
    }

    upstream rbackend_2 {
        server 127.0.0.1:%%PORT_8082%% sid=bb;
        sticky cookie sticky;
    }

    upstream rbackend_3 {
        server 127.0.0.1:%%PORT_8083%% sid=ccc;
        sticky cookie sticky;
    }

    upstream rbackend_4 {
        server 127.0.0.1:%%PORT_8084%% sid=ddd;
        sticky cookie sticky;
    }

    upstream rbackend_5 {
        server 127.0.0.1:%%PORT_8085%% sid=eee;
        sticky cookie sticky;
    }

    upstream sslbackend_1 {
        server 127.0.0.1:%%PORT_9081%%;
        sticky cookie sticky;
    }
    upstream sslbackend_2 {
        server 127.0.0.1:%%PORT_9082%%;
        sticky cookie sticky;
    }
    upstream sslbackend_3 {
        server 127.0.0.1:%%PORT_9083%%;
        sticky cookie sticky;
    }
    upstream sslbackend_4 {
        server 127.0.0.1:%%PORT_9084%%;
        sticky cookie sticky;
    }
    upstream sslbackend_5 {
        server 127.0.0.1:%%PORT_9085%%;
        sticky cookie sticky;
    }

    # Upstreams for test cases: 1 upstream per testcase

    upstream tc_1 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;
        server 127.0.0.1:%%PORT_8084%%;
        server 127.0.0.1:%%PORT_8085%%;
    }

    map foo $empty {
        default: "";
    }

    map bar $attr {
        default "e=f";
    }

    upstream tc_2 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        sticky cookie sticky a=b c=d $empty $attr;
    }

    upstream tc_3 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        least_conn;

        # zero default attr, zero foo attr, set attr with variable
        sticky cookie sticky path= foo= s=$scheme Max-Age=;
    }

    upstream tc_4 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        ip_hash;
        sticky cookie sticky;
    }

    upstream tc_5 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        hash $remote_addr;
        sticky cookie sticky;
    }

    upstream tc_6 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        random;
        sticky cookie sticky;
    }

    upstream tc_7 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        sticky cookie sticky;
        keepalive 4;
    }

    upstream tc_8 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        keepalive 4;
        sticky cookie sticky;
    }

    upstream tc_9 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        least_conn;
        keepalive 4;
        sticky cookie sticky;
    }

    upstream tc_10 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        least_conn;
        sticky cookie sticky;
        keepalive 4;
    }

    upstream tc_11 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;
        sticky cookie sticky;
        sticky_secret hidden$arg_foo;
    }

    upstream tc_12 {
        server 127.0.0.1:%%PORT_8081%% sid=a;
        server 127.0.0.1:%%PORT_8082%% sid=bb;
        sticky cookie sticky;
    }

    upstream tc_13 {
        server 127.0.0.1:%%PORT_8081%% sid=a;
        server 127.0.0.1:%%PORT_8082%% sid=bb;

        sticky route $arg_route;
    }

    upstream tc_14 {
        server 127.0.0.1:%%PORT_8081%% down;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;

        sticky cookie sticky;
        sticky_strict on;
    }

    upstream tc_15 {
        server 127.0.0.1:%%PORT_8081%% down;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;

        hash $remote_addr;
        sticky cookie sticky;
        sticky_strict on;
    }

    upstream tc_16 {
        server 127.0.0.1:%%PORT_8081%% down;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;

        ip_hash;
        sticky cookie sticky;
        sticky_strict on;
    }

    upstream tc_17 {
        server 127.0.0.1:%%PORT_8081%% down;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;

        least_conn;
        sticky cookie sticky;
        sticky_strict on;
    }

    upstream tc_18 {
        server 127.0.0.1:%%PORT_8081%% down;
        server 127.0.0.1:%%PORT_8082%%;
        server 127.0.0.1:%%PORT_8083%%;

        random;
        sticky cookie sticky;
        sticky_strict on;
    }

    upstream tc_19 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;

        sticky cookie sticky;
    }

    # ssl upstreams
    upstream tc_20 {
        server 127.0.0.1:%%PORT_9081%%;
        server 127.0.0.1:%%PORT_9082%%;

        sticky cookie sticky;
    }

    # proxy_pass with variables
    upstream tc_21 {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;

        sticky cookie sticky;
    }

    upstream tc_22_a {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;

        sticky cookie sca;
    }

    upstream tc_22_b {
        server 127.0.0.1:%%PORT_8081%%;
        server 127.0.0.1:%%PORT_8082%%;

        sticky cookie scb;
    }

    upstream tc_23 {
        server 127.0.0.1:%%PORT_8085%%;
        server 127.0.0.1:%%PORT_8082%%;

        sticky cookie sticky;
    }

    upstream tc_24 {
        server 127.0.0.1:%%PORT_8081%% fail_timeout=0 max_fails=0;
        server 127.0.0.1:%%PORT_8082%% fail_timeout=0 max_fails=0;
        server 127.0.0.1:%%PORT_8083%% backup;
        server 127.0.0.1:%%PORT_8084%% backup;

        sticky cookie sticky;
    }

    upstream tc_25 {
        server 127.0.0.1:%%PORT_8081%% fail_timeout=0 max_fails=0;
        server 127.0.0.1:%%PORT_8082%% fail_timeout=0 max_fails=0;
        server 127.0.0.1:%%PORT_8083%% backup;
        server 127.0.0.1:%%PORT_8084%% backup;

        sticky cookie sticky;
        sticky_strict on;
    }

    server {
        listen       127.0.0.1:%%PORT_8080%%;

        # Entry points for test harness

        location /backend_1 { proxy_pass http://backend_1/; }
        location /backend_2 { proxy_pass http://backend_2/; }
        location /backend_3 { proxy_pass http://backend_3/; }
        location /backend_4 { proxy_pass http://backend_4/; }
        location /backend_5 { proxy_pass http://backend_5/; }

        location /sbackend_1 { proxy_pass http://sbackend_1/; }
        location /sbackend_2 { proxy_pass http://sbackend_2/; }
        location /sbackend_3 { proxy_pass http://sbackend_3/; }
        location /sbackend_4 { proxy_pass http://sbackend_4/; }
        location /sbackend_5 { proxy_pass http://sbackend_5/; }

        location /rbackend_1 { proxy_pass http://rbackend_1/; }
        location /rbackend_2 { proxy_pass http://rbackend_2/; }
        location /rbackend_3 { proxy_pass http://rbackend_3/; }
        location /rbackend_4 { proxy_pass http://rbackend_4/; }
        location /rbackend_5 { proxy_pass http://rbackend_5/; }

        location /sslbackend_1 { proxy_pass https://sslbackend_1/; }
        location /sslbackend_2 { proxy_pass https://sslbackend_2/; }
        location /sslbackend_3 { proxy_pass https://sslbackend_3/; }
        location /sslbackend_4 { proxy_pass https://sslbackend_4/; }
        location /sslbackend_5 { proxy_pass https://sslbackend_5/; }

        # Entry points for corresponding test cases

        location /tc_1 { proxy_pass http://tc_1; }
        location /tc_2 { proxy_pass http://tc_2; }
        location /tc_3 { proxy_pass http://tc_3; }
        location /tc_4 { proxy_pass http://tc_4; }
        location /tc_5 { proxy_pass http://tc_5; }
        location /tc_6 { proxy_pass http://tc_6; }
        location /tc_7 {
            proxy_pass http://tc_7;
            proxy_http_version 1.1;
        }
        location /tc_8 {
            proxy_pass http://tc_8;
            proxy_http_version 1.1;
        }
        location /tc_9 {
            proxy_pass http://tc_9;
            proxy_http_version 1.1;
        }
        location /tc_10 {
            proxy_pass http://tc_10;
            proxy_http_version 1.1;
        }

        location /tc_11 { proxy_pass http://tc_11; }
        location /tc_12 { proxy_pass http://tc_12; }
        location /tc_13 { proxy_pass http://tc_13; }
        location /tc_14 { proxy_pass http://tc_14; }
        location /tc_15 { proxy_pass http://tc_15; }
        location /tc_16 { proxy_pass http://tc_16; }
        location /tc_17 { proxy_pass http://tc_17; }
        location /tc_18 { proxy_pass http://tc_18; }
        location /tc_19 { proxy_pass http://tc_19; }
        location /tc_20 { proxy_pass https://tc_20; }

        location /tc_21 {
            set $tc21 tc_21;
            proxy_pass http://$tc21;
        }
        location /tc_22 {
            proxy_pass http://$arg_u/;
        }

        location /tc_23 {
            proxy_pass http://tc_23;
            proxy_next_upstream http_502;
        }

        location /tc_24 {
            proxy_pass http://tc_24/;
            proxy_next_upstream http_503;
        }

        location /tc_25 {
            proxy_pass http://tc_25/;
            proxy_next_upstream http_503;
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
            return 200 B3;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8084%%;
        listen       127.0.0.1:%%PORT_9084%% ssl;
        location / {
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

my @ports = my ($p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10) =
    (port(8081), port(8082), port(8083), port(8084), port(8085),
     port(9081), port(9082), port(9083), port(9084), port(9085));

# wait for all backends to be available
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8083));
$t->waitforsocket('127.0.0.1:' . port(8084));
$t->waitforsocket('127.0.0.1:' . port(8085));

$t->waitforsocket('127.0.0.1:' . port(9081));
$t->waitforsocket('127.0.0.1:' . port(9082));
$t->waitforsocket('127.0.0.1:' . port(9083));
$t->waitforsocket('127.0.0.1:' . port(9084));
$t->waitforsocket('127.0.0.1:' . port(9085));

###############################################################################

# prepare for testing: get sticky cookies for all backends

my %bmap = collect_cookies("/backend_");
my %smap = collect_cookies("/sbackend_", "foo=bazz");
my %rmap = collect_cookies("/rbackend_");
my %sslmap = collect_cookies("/sslbackend_");

###############################################################################

tc1("rr regression");
tc2("Sticky cookie basic with rr");
tc3("Sticky cookie basic with least_conn");
tc4("Sticky cookie basic with ip_hash");
tc5("Sticky cookie basic with hash");
tc6("Sticky cookie basic with random");
tc7("Sticky with keepalive (pre)");
tc8("Sticky with keepalive (post)");
tc9("Sticky with keepalive and LB (pre)");
tc10("Sticky with keepalive and LB (post)");
tc11("Sticky cookie secret");
tc12("Sticky cookie with route");
tc13("Sticky route basic");
tc14("Sticky strict with rr");
tc15("Sticky strict with hash");
tc16("Sticky strict with ip_hash");
tc17("Sticky strict with least_conn");
tc18("Sticky strict with random");
tc19("Sticky cookie garbage");
tc20("Sticky cookie with ssl");
tc21("Sticky cookie with variable proxy_pass");
tc22("Sticky with implicit upstreams");
tc23("Sticky with proxy_next_upstream");
tc24("Sticky with backup");
tc25("Sticky strict with backup");

###############################################################################

# regression: no cookie is set, RR works normally
# - upstream has no sticky directive, no keepalive
# - make 4 requests, expect 4 responses from corresponding backends, in order
sub tc1 {
    annotate(@_);

    my ($backend, $cookie);
    my %res;

    for (1 .. 4) {
        %res = get_sticky_reply("/tc_1");
        $backend = $res{"backend"};
        $cookie = $res{"cookie"};

        is($backend, "B$_", "backend is selected by RR");
        is($cookie, undef, "no cookie is set for backend $_");
    }
}

# basic test for 'sticky cookie' mode:
#  - cookie is set
#  - attributes a, c are set, empty skipped, defualt path set
#  - request w/o cookie result in different backends
#  - request with cookie goes to corresponding backend
sub tc2 {
    annotate(@_);

    my ($backend, $cookie, $attrs, $code);

    my %res;

    # normal request
    for (1 .. 2) {
        %res = get_sticky_reply("/tc_2");
        $backend = $res{"backend"};
        $cookie = $res{"cookie"};
        $code = $res{"code"};

        is($backend, "B$_", "backend is selected by RR");
        is($cookie, $bmap{$backend}, "cookie is correct for backend $_");
        is($code, "200", "response is 200 OK");

        $attrs = $res{"attrs"};
        my ($a) = $attrs =~ /a=(\w+)/;
        my ($c) = $attrs =~ /c=(\w+)/;
        my ($e) = $attrs =~ /e=(\w+)/;

        is($a, "b", "first attr is good");
        is($c, "d", "second attr is good");
        is($e, "f", "variable attr is good");

        is($attrs, "a=b; c=d; e=f; path=/",
           "no extra in attributes, defaults set");
    }

    verify_sticky_upstream("/tc_2", \%bmap);
}


# testcase 3..6 - verify that sticky works with different load balancers
# additionally, in tc3 test some default attributes
sub tc3 {
    annotate(@_);
    verify_sticky_upstream("/tc_3", \%bmap);

    my $attrs;
    my %res;

    %res = get_sticky_reply("/tc_3");

    $attrs = $res{"attrs"};

    is($attrs, "s=http", "default attrs zeroed, varattr is set");
}

sub tc4 {
    annotate(@_);
    verify_sticky_upstream("/tc_4", \%bmap);
}

sub tc5 {
    annotate(@_);
    verify_sticky_upstream("/tc_5", \%bmap);
}

sub tc6 {
    annotate(@_);
    verify_sticky_upstream("/tc_6", \%bmap);
}

# testcases 7..10: verify that sticky still workis if keepalive is enabled
# in various combinations in config
sub tc7 {
    annotate(@_);

    verify_rr('/tc_7', 2, 4);
    verify_sticky_upstream("/tc_7", \%bmap);
}

sub tc8 {
    annotate(@_);

    verify_rr('/tc_8', 2, 4);
    verify_sticky_upstream("/tc_8", \%bmap);
}

sub tc9 {
    annotate(@_);

    verify_rr('/tc_9', 2, 4);
    verify_sticky_upstream("/tc_9", \%bmap);
}

sub tc10 {
    annotate(@_);

    verify_rr('/tc_10', 2, 4);
    verify_sticky_upstream("/tc_10", \%bmap);
}


# verifies 'sticky secret' option
sub tc11 {
    annotate(@_);

    verify_sticky_upstream("/tc_11?foo=bazz", \%smap);

    # try to stick with bad password in argument
    # make request with (bad) sticky cookie - expect round-robin
    verify_rr('/tc_11?foo=blah', 2, 2, $smap{"B2"});
}

# verify sticky cookie with sid= backends
sub tc12 {
    annotate(@_);

    verify_rr('/tc_12', 2, 4);
    verify_sticky_upstream("/tc_12", \%rmap);
}

# ensure backends are selected by $arg_route
sub tc13 {
    annotate(@_);

    verify_rr('/tc_13', 2, 4);
    verify_route_upstream("/tc_13", \%rmap);
}

# testcases 14..18 - verify 'sticky strict' with various balancers
# if sticky_strict enabled, 502 is returned, if backend is not available
sub tc14 {
    annotate(@_);

    verify_strict("/tc_14");
}

sub tc15 {
    annotate(@_);

    verify_strict("/tc_15");
}

sub tc16 {
    annotate(@_);

    verify_strict("/tc_16");
}

sub tc17 {
    annotate(@_);

    verify_strict("/tc_17");
}

sub tc18 {
    annotate(@_);

    verify_strict("/tc_18");
}

# coverage: send some garbage in sticky cookie and verify we get RR
sub tc19 {
    annotate(@_);

    # generate long cookie with len > 32
    my $cookie = "0123456789" x 4;

    # verify that we get RR with such poor cookie
    verify_rr('/tc_19', 2, 4, $cookie);
}

# coverage: backends via SSL, to verify set/save session is called
sub tc20 {
    annotate(@_);

    verify_sticky_upstream("/tc_20", \%sslmap);
}

# verify sticky works if upstream is defined by variable
sub tc21 {
    annotate(@_);

    verify_sticky_upstream("/tc_21", \%bmap);
}

# verify how sticky works with implicit upstreams
sub tc22 {
    annotate(@_);

    my %res;

    %res = get_sticky_reply("/tc_22?u=127.0.0.1:".port(8081));

    is($res{"backend"}, "B1", "implicit backend B1");
    is($res{"code"}, "200", "implicit backend response good");
    is($res{"cookie"}, undef, "no sticky cookie");

    # check cookie name is correct when different upstreams selected
    %res = get_sticky_reply("/tc_22?u=tc_22_a");

    is($res{"backend"}, "B1", "var upstream selects B1");
    is($res{"cookie"}, $bmap{"B1"}, "sticky cookie set");
    is($res{"cookie_name"},  "sca" , "sticky cookie name is correct for a");

    %res = get_sticky_reply("/tc_22?u=tc_22_b");

    is($res{"backend"}, "B1", "var upstream selects B1");
    is($res{"cookie"}, $bmap{"B1"}, "sticky cookie set");
    is($res{"cookie_name"},  "scb" , "sticky cookie name is correct for b");
}


# verify sticky with proxy next upstream
sub tc23 {
    annotate(@_);

    my %res;

    %res = get_sticky_reply("/tc_23", $bmap{"B5"});

    is($res{"backend"}, "B2", "B2 is selected instead of B5");
    is($res{"cookie"}, $bmap{"B2"}, "cookie is set for B2");

}

# verify sticky with backup servers
sub tc24 {
    annotate(@_);

     my %res;

    %res = get_sticky_reply("/tc_24/bad");

    # expect B1 and B2 to fail, B3 is selected from backup
    is($res{"cookie"}, $bmap{"B3"}, "cookie is set for B3");

    # RR will select B3 from backup again
    %res = get_sticky_reply("/tc_24", $bmap{"B3"});
    is($res{"cookie"}, $bmap{"B3"}, "cookie is again from B3");
}

# verify sticky with backup servers and 'strict' option
sub tc25 {
    annotate(@_);

     my %res;

    %res = get_sticky_reply("/tc_25/bad");

    # expect B1 and B2 to fail, B3 is selected from backup
    is($res{"cookie"}, $bmap{"B3"}, "cookie is set for B3");

    # strict sticky gets request to backup backend
    %res = get_sticky_reply("/tc_25", $bmap{"B3"});
    is($res{"cookie"}, $bmap{"B3"}, "request is stick to backup");
}

###############################################################################

sub annotate {
    my ($tc) = @_;

    if ($debug != 1) {
        return;
    }

    my $tname = (split(/::/, (caller(1))[3]))[1];
    print("# ***  $tname: $tc \n");
}

# makes an HTTP request to passed $uri (with optional cookie)
# returns hash with various response properties: backend, cookie, attrs, code
sub get_sticky_reply {

    my ($uri, $sticky_cookie, $cookie_name) = @_;

    my $response;

    if (!defined($cookie_name)) {
        $cookie_name = "sticky";
    }

    if (defined($sticky_cookie)) {
        $response = http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
Cookie: $cookie_name=$sticky_cookie

EOF
    } else {
        $response = http_get($uri);
    }

    my ($backend) = $response =~ /X-Backend: (B\d+)/;
    my ($resp_cookie_name) = $response =~ /Set-Cookie: (\w+)=\w+/;
    my ($cookie) = $response =~ /Set-Cookie: \w+=(\w+)/;
    my ($attrs) = $response =~ /Set-Cookie: \w+=\w+; (.*)\r\n/;
    my ($code) = $response =~ qr!HTTP/1.1 (\d\d\d)!ms;
    my %result;

    $result{"backend"} = $backend;
    $result{"cookie"} = $cookie;
    $result{"cookie_name"} = $resp_cookie_name;
    $result{"attrs"} = $attrs;
    $result{"code"} = $code;

    return %result;
}

# visits all backends via /backend_NNN uri and returns
# hash with backend <-> cookie mapping
sub collect_cookies {
    my ($uri_template, $secret_arg) = @_;

    my (%backend_cookies, %result);

    my ($backend, $cookie);

    if ($debug) {
        print("# Backend cookies [$uri_template]:\n");
    }

    my $url;

    for (1 .. 5) {

        if (!defined($secret_arg)) {
            $url = " $uri_template$_/good";
        } else {
            $url = " $uri_template$_/good?$secret_arg";
        }

        %result = get_sticky_reply($url);

        $backend = $result{"backend"};
        $cookie = $result{"cookie"};

        if ($debug) {
            print("#    $backend <=> $cookie\n");
        }
        $backend_cookies{$backend} = $cookie;
    }

    return %backend_cookies;
}

###############################################################################

# verify that both backends in upstream are sticked via cookie
sub verify_sticky_upstream {
    my ($uri, $bmap) = @_;

    verify_sticky_cookie($uri, $bmap->{"B2"}, "B2");
    verify_sticky_cookie($uri, $bmap->{"B1"}, "B1");
}


# verify that both backends in upstream are sticked via route
sub verify_route_upstream {
    my ($uri, $bmap) = @_;

    verify_sticky_route($uri, $bmap->{"B2"}, "B2");
    verify_sticky_route($uri, $bmap->{"B1"}, "B1");
}


# perform: send request to $uri 4 times with cookie for $backend
# verify:  same backend with proper cookie is returned all times
sub verify_sticky_cookie {
    my ($uri, $cookie, $backend) = @_;

    my $n = 4;
    my %res;

    my $expected = ($backend.$cookie) x $n;
    my $actual;

    for (1..$n) {
        %res = get_sticky_reply($uri, $cookie);
        $actual .= $res{"backend"};
        $actual .= $res{"cookie"};
    }

    is($expected, $actual, "request to $uri and backend $backend is sticky");
}


# perform: send request to $uri 4 times with route for $backend
# verify:  same backend is returned all times
sub verify_sticky_route {
    my ($uri, $route, $backend) = @_;

    my $n = 4;
    my %res;

    my $cookies = '';
    my $expected = ($backend) x $n;
    my $actual;

    for (1..$n) {
        %res = get_sticky_reply($uri."?route=$route");
        $actual .= $res{"backend"};
        if (defined($res{"cookie"})) {
            $cookies .= $res{"cookie"};
        }
    }

    is($expected, $actual, "request to $uri and backend $backend is sticky");
    is($cookies, "", "no cookies set in route mode");
}


# tests how 'sticky strict' option works
sub verify_strict {
    my ($uri) = @_;

    my %res;

    %res = get_sticky_reply($uri, $bmap{"B1"});

    # sticky request to down server is bad
    is($res{"code"}, 502, "sticky request to u/a server returns 502");

    # request without sticky is served ok
    %res = get_sticky_reply($uri);
    is($res{"code"}, 200, "there are alive servers in same backend");

    # sticky request to good server is ok
    %res = get_sticky_reply($uri, $bmap{"B2"});
    is($res{"code"}, 200, "B2 is good");
    is($res{"cookie"}, $bmap{"B2"}, "sticky cookie match");
    is($res{"backend"}, "B2", "backend match");
}


# increment key in hash or create new key
sub inckey {
    my ($hash, $key) = @_;

    if (!defined($hash->{$key})) {
        $hash->{$key} = 1;
    } else {
        $hash->{$key} = $hash->{$key} + 1;
    }
}


# perform $n x $nb requests (assuming $nb backends)
# expect equal number of responses ($n) from each backend
sub verify_rr {
    my ($uri, $nb, $n, $cookie) = @_;
    my (%reply, $back, %distr);

    my $total = $nb * $n;

    for (1 .. $total) {
        %reply = get_sticky_reply($uri, $cookie);

        inckey(\%distr, $reply{"backend"});
    }

    for (1 .. $nb) {
        is ($distr{"B$_"}, $n, "RR check: backend B$_ got $n/$total requests");
    }
}
