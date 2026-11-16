#!/usr/bin/perl

# (C) 2025 Web Server LLC
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for TLS early data with HTTP/3.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_api http_v3 cryptx/)
	->has_daemon('openssl')->plan(19)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    add_header X-Session $ssl_session_reused always;
    add_header X-Early   $ssl_early_data     always;

    server {
        listen      127.0.0.1:8080;

        location /status/ {
            api /status/;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;
        status_zone  ssl_early_data_on;

        ssl_early_data on;
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;
        status_zone  ssl_early_data_off;

        ssl_early_data off;
    }
}

EOF

$t->prepare_ssl();
$t->run();

###############################################################################

# ssl_early_data: on

my $before1 = get_ssl_stats('ssl_early_data_on');

my $s = Test::Nginx::HTTP3->new(8980);
my $frames = $s->read(all => [{ sid => $s->new_stream(), fin => 1 }]);

my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-session'}, '.', 'new session');
is($frame->{headers}->{'x-early'}, undef, 'on: new session not early');

my $psk_list = $s->{psk_list};

$s = Test::Nginx::HTTP3->new(8980, psk_list => $psk_list, early_data => {},
	start_chain => 1);

TODO: {
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL');
local $TODO = 'no 0-RTT in OpenSSL compat layer'
	unless $t->has_module('OpenSSL [.0-9]+\+quic')
	or $t->has_feature('openssl:3.5.1')
	or $t->has_module('BoringSSL|AWS-LC')
	or $t->has_module('LibreSSL');

$frames = $s->read(all => [{ sid => 0, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-session'}, 'r', 'reused session 0rtt');
is($frame->{headers}->{'x-early'}, '1', 'reused session is early');

}

# includes sending some initial 1-RTT data

$s->send_chain();

$frames = $s->read(all => [{ type => 'HANDSHAKE_DONE' }], wait => 0.5);

($frame) = grep { $_->{type} eq "HANDSHAKE_DONE" } @$frames;
ok($frame, '1rtt after discarding 0rtt');

$frames = $s->read(all => [{ sid => $s->new_stream(), fin => 1 }]);

TODO: {
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL');

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{'x-session'}, 'r', 'reused session 1rtt');

}

is($frame->{headers}->{'x-early'}, undef, 'reused session not early');

my $after1 = get_ssl_stats('ssl_early_data_on');

is($after1->{handshaked} - $before1->{handshaked}, 2,
	'stats: 2 successful handshakes counted (on)');

TODO: {
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL');

is($after1->{reuses} - $before1->{reuses}, 1,
	'stats: 1 session reuse counted (on, via early data)');
}

is($after1->{failed}, $before1->{failed}, 'stats: no failed handshakes (on)');

# ssl_early_data: off

my $before2 = get_ssl_stats('ssl_early_data_off');

my $s2 = Test::Nginx::HTTP3->new(8981);
my $frames2 = $s2->read(all => [{ sid => $s2->new_stream(), fin => 1 }]);

my ($frame2) = grep { $_->{type} eq "HEADERS" } @$frames2;
is($frame2->{headers}->{'x-session'}, '.', 'off: new session');
is($frame2->{headers}->{'x-early'}, undef, 'off: new session not early');

my $psk_list2 = $s2->{psk_list};

$s2 = Test::Nginx::HTTP3->new(8981, psk_list => $psk_list2, early_data => {},
	start_chain => 1);

# with ssl_early_data off, the server must not process 0-RTT data at all;
# the client-sent early data should only be consumed after full 1-RTT
# handshake completes, so no HEADERS frame should show up before that
$frames2 = $s2->read(all => [{ sid => 0, fin => 1 }], wait => 0.5);
($frame2) = grep { $_->{type} eq "HEADERS" } @$frames2;
ok(!$frame2, 'off: no early response before handshake done');

$s2->send_chain();

$frames2 = $s2->read(all => [{ type => 'HANDSHAKE_DONE' }], wait => 0.5);
($frame2) = grep { $_->{type} eq "HANDSHAKE_DONE" } @$frames2;
ok($frame2, 'off: 1rtt handshake completes normally');

$frames2 = $s2->read(all => [{ sid => $s2->new_stream(), fin => 1 }]);

TODO: {
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL');

($frame2) = grep { $_->{type} eq "HEADERS" } @$frames2;
is($frame2->{headers}->{'x-session'}, 'r', 'off: reused session 1rtt');

}

is($frame2->{headers}->{'x-early'}, undef, 'off: reused session not early');

my $after2 = get_ssl_stats('ssl_early_data_off');

is($after2->{handshaked} - $before2->{handshaked}, 2,
	'stats: 2 successful handshakes counted (off)');

TODO: {
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL');
is($after2->{reuses} - $before2->{reuses}, 1,
	'stats: 1 session reuse counted (off, via regular 1-RTT)');
}

is($after2->{failed}, $before2->{failed}, 'stats: no failed handshakes (off)');

###############################################################################

sub get_ssl_stats {
	my ($zone) = @_;
	return get_json("/status/http/server_zones/$zone/ssl");
}

###############################################################################
