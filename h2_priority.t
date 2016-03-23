#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for HTTP/2 protocol with priority.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2 qw/ :DEFAULT :frame /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2/)->plan(20)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 http2;
        server_name  localhost;
    }
}

EOF

$t->run();

# file size is slightly beyond initial window size: 2**16 + 80 bytes

$t->write_file('t1.html',
	join('', map { sprintf "X%04dXXX", $_ } (1 .. 8202)));

$t->write_file('t2.html', 'SEE-THIS');

###############################################################################

# stream muliplexing + PRIORITY frames

my $sess = new_session();
my $sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

my $sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_priority($sess, 0, $sid);
h2_priority($sess, 255, $sid2);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

my $frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

my @data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "$sid2 $sid", 'weight - PRIORITY 1');

# and vice versa

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_priority($sess, 255, $sid);
h2_priority($sess, 0, $sid2);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
is(join(' ', map { $_->{sid} } @data), "$sid $sid2", 'weight - PRIORITY 2');

# stream muliplexing + HEADERS PRIORITY flag

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html', prio => 0 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', prio => 255 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
my $sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'weight - HEADERS PRIORITY 1');

# and vice versa

$sess = new_session();
$sid = new_stream($sess, { path => '/t1.html', prio => 255 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', prio => 0 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 }
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'weight - HEADERS PRIORITY 2');

# 5.3.1.  Stream Dependencies

# PRIORITY frame

$sess = new_session();

h2_priority($sess, 16, 3, 0);
h2_priority($sess, 16, 1, 3);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'dependency - PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 1);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'dependency - PRIORITY 2');

# PRIORITY - self dependency

# 5.3.1.  Stream Dependencies
#   A stream cannot depend on itself.  An endpoint MUST treat this as a
#   stream error of type PROTOCOL_ERROR.

$sess = new_session();
$sid = new_stream($sess);
h2_read($sess, all => [{ sid => $sid, fin => 1 }]);

h2_priority($sess, 0, $sid, $sid);
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

my ($frame) = grep { $_->{type} eq "RST_STREAM" } @$frames;
is($frame->{sid}, $sid, 'dependency - PRIORITY self - RST_STREAM');
is($frame->{code}, 1, 'dependency - PRIORITY self - PROTOCOL_ERROR');

# HEADERS PRIORITY flag, reprioritize prior PRIORITY frame records

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 0);

$sid = new_stream($sess, { path => '/t1.html', dep => 3 });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid2 $sid", 'dependency - HEADERS PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 0);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html', dep => 1 });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

h2_window($sess, 2**17, $sid);
h2_window($sess, 2**17, $sid2);
h2_window($sess, 2**17);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid $sid2", 'dependency - HEADERS PRIORITY 2');

# HEADERS - self dependency

$sess = new_session();
$sid = new_stream($sess, { dep => 1 });
$frames = h2_read($sess, all => [{ type => 'RST_STREAM' }]);

($frame) = grep { $_->{type} eq "RST_STREAM" } @$frames;
is($frame->{sid}, $sid, 'dependency - HEADERS self - RST_STREAM');
is($frame->{code}, 1, 'dependency - HEADERS self - PROTOCOL_ERROR');

# PRIORITY frame, weighted dependencies

$sess = new_session();

h2_priority($sess, 16, 5, 0);
h2_priority($sess, 255, 1, 5);
h2_priority($sess, 0, 3, 5);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

my $sid3 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid3, fin => 0x4 }]);

h2_window($sess, 2**16, 1);
h2_window($sess, 2**16, 3);
h2_window($sess, 2**16, 5);
h2_window($sess, 2**16);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid3 $sid $sid2", 'weighted dependency - PRIORITY 1');

# and vice versa

$sess = new_session();

h2_priority($sess, 16, 5, 0);
h2_priority($sess, 0, 1, 5);
h2_priority($sess, 255, 3, 5);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid2, fin => 0x4 }]);

$sid3 = new_stream($sess, { path => '/t2.html' });
h2_read($sess, all => [{ sid => $sid3, fin => 0x4 }]);

h2_window($sess, 2**16, 1);
h2_window($sess, 2**16, 3);
h2_window($sess, 2**16, 5);
h2_window($sess, 2**16);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid2, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

@data = grep { $_->{type} eq "DATA" } @$frames;
$sids = join ' ', map { $_->{sid} } @data;
is($sids, "$sid3 $sid2 $sid", 'weighted dependency - PRIORITY 2');

# PRIORITY - reprioritization with circular dependency - after [3] removed
# initial dependency tree:
# 1 <- [3] <- 5

$sess = new_session();

h2_window($sess, 2**18);

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 1);
h2_priority($sess, 16, 5, 3);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid2, length => 2**16 - 1 }]);

$sid3 = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid3, length => 2**16 - 1 }]);

h2_window($sess, 2**16, $sid2);

$frames = h2_read($sess, all => [{ sid => $sid2, fin => 1 }]);
$sids = join ' ', map { $_->{sid} } grep { $_->{type} eq "DATA" } @$frames;
is($sids, $sid2, 'removed dependency');

for (1 .. 40) {
	h2_read($sess, all => [{ sid => new_stream($sess), fin => 1 }]);
}

# make circular dependency
# 1 <- 5 -- current dependency tree before reprioritization
# 5 <- 1
# 1 <- 5

h2_priority($sess, 16, 1, 5);
h2_priority($sess, 16, 5, 1);

h2_window($sess, 2**16, $sid);
h2_window($sess, 2**16, $sid3);

$frames = h2_read($sess, all => [
	{ sid => $sid, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == $sid } @$frames;
is($frame->{length}, 81, 'removed dependency - first stream');

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == $sid3 } @$frames;
is($frame->{length}, 81, 'removed dependency - last stream');

# PRIORITY - reprioritization with circular dependency - exclusive [5]
# 1 <- [5] <- 3

$sess = new_session();

h2_window($sess, 2**18);

h2_priority($sess, 16, 1, 0);
h2_priority($sess, 16, 3, 1);
h2_priority($sess, 16, 5, 1, excl => 1);

$sid = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid, length => 2**16 - 1 }]);

$sid2 = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid2, length => 2**16 - 1 }]);

$sid3 = new_stream($sess, { path => '/t1.html' });
h2_read($sess, all => [{ sid => $sid3, length => 2**16 - 1 }]);

h2_window($sess, 2**16, $sid);

$frames = h2_read($sess, all => [{ sid => $sid, fin => 1 }]);
$sids = join ' ', map { $_->{sid} } grep { $_->{type} eq "DATA" } @$frames;
is($sids, $sid, 'exclusive dependency - parent removed');

# make circular dependency
# 5 <- 3 -- current dependency tree before reprioritization
# 3 <- 5

h2_priority($sess, 16, 5, 3);

h2_window($sess, 2**16, $sid2);
h2_window($sess, 2**16, $sid3);

$frames = h2_read($sess, all => [
	{ sid => $sid2, fin => 1 },
	{ sid => $sid3, fin => 1 },
]);

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == $sid2 } @$frames;
is($frame->{length}, 81, 'exclusive dependency - first stream');

($frame) = grep { $_->{type} eq "DATA" && $_->{sid} == $sid3 } @$frames;
is($frame->{length}, 81, 'exclusive dependency - last stream');

###############################################################################
