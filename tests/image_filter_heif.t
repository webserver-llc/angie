#!/usr/bin/perl

# (C) 2025 Web Server LLC

# Tests for image filter module, AVIF and HEIC support.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Utils qw/get_json/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require GD; };
plan(skip_all => 'GD not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http image_filter/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen %%PORT_8080%%;
        server_name localhost;

        location /test {
            image_filter test;
            alias %%TESTDIR%%/;
        }

        location /resize {
            image_filter resize 5 5;
            alias %%TESTDIR%%/;
        }

        location /size {
            image_filter size;
            alias %%TESTDIR%%/;
        }

        location /avif_quality {
            image_filter rotate 90;
            image_filter_avif_quality 50 7;
            alias %%TESTDIR%%/;
        }

        location /heic_quality {
            image_filter rotate 180;
            image_filter_heic_quality 50;
            alias %%TESTDIR%%/;
        }

        location /avif_quality_var {
            image_filter rotate 90;
            image_filter_avif_quality $arg_q $arg_s;
            alias %%TESTDIR%%/;
        }

        location /heic_quality_var {
            image_filter rotate 180;
            image_filter_heic_quality $arg_q;
            alias %%TESTDIR%%/;
        }
    }
}

EOF

# simple.avif
# 00000000: 0000 0020 6674 7970 6176 6966 0000 0000  ... ftypavif....
# 00000010: 6176 6966 6d69 6631 6d69 6166 4d41 3142  avifmif1miafMA1B
# 00000020: 0000 00f2 6d65 7461 0000 0000 0000 0028  ....meta.......(
# 00000030: 6864 6c72 0000 0000 0000 0000 7069 6374  hdlr........pict
# 00000040: 0000 0000 0000 0000 0000 0000 6c69 6261  ............liba
# 00000050: 7669 6600 0000 000e 7069 746d 0000 0000  vif.....pitm....
# 00000060: 0001 0000 001e 696c 6f63 0000 0000 4400  ......iloc....D.
# 00000070: 0001 0001 0000 0001 0000 011a 0000 0050  ...............P
# 00000080: 0000 0028 6969 6e66 0000 0000 0001 0000  ...(iinf........
# 00000090: 001a 696e 6665 0200 0000 0001 0000 6176  ..infe........av
# 000000a0: 3031 436f 6c6f 7200 0000 006a 6970 7270  01Color....jiprp
# 000000b0: 0000 004b 6970 636f 0000 0014 6973 7065  ...Kipco....ispe
# 000000c0: 0000 0000 0000 000a 0000 0006 0000 0010  ................
# 000000d0: 7069 7869 0000 0000 0308 0808 0000 000c  pixi............
# 000000e0: 6176 3143 8100 0c00 0000 0013 636f 6c72  av1C........colr
# 000000f0: 6e63 6c78 0001 000d 0001 8000 0000 1769  nclx...........i
# 00000100: 706d 6100 0000 0000 0000 0100 0104 0102  pma.............
# 00000110: 8304 0000 0058 6d64 6174 1200 0a08 180c  .....Xmdat......
# 00000120: a6b0 4043 4061 3242 1340 0208 2085 00c9  ..@C@a2B.@.. ...
# 00000130: d069 b945 9c7a 4242 aedc 3ce4 fe3c a3b5  .i.E.zBB..<..<..
# 00000140: 5093 1f12 1ea0 acb4 fafc e6ab 1214 cc64  P..............d
# 00000150: c61b e53d 6f96 ae1a 23b7 1945 1ce4 e4b3  ...=o...#..E....
# 00000160: 3ea6 72a0 9b36 b710 d0e8                 >.r..6....

$t->write_file('simple.avif',
	  "\x00\x00\x00\x20\x66\x74\x79\x70\x61\x76\x69\x66\x00\x00\x00\x00"
	. "\x61\x76\x69\x66\x6d\x69\x66\x31\x6d\x69\x61\x66\x4d\x41\x31\x42"
	. "\x00\x00\x00\xf2\x6d\x65\x74\x61\x00\x00\x00\x00\x00\x00\x00\x28"
	. "\x68\x64\x6c\x72\x00\x00\x00\x00\x00\x00\x00\x00\x70\x69\x63\x74"
	. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6c\x69\x62\x61"
	. "\x76\x69\x66\x00\x00\x00\x00\x0e\x70\x69\x74\x6d\x00\x00\x00\x00"
	. "\x00\x01\x00\x00\x00\x1e\x69\x6c\x6f\x63\x00\x00\x00\x00\x44\x00"
	. "\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x01\x1a\x00\x00\x00\x50"
	. "\x00\x00\x00\x28\x69\x69\x6e\x66\x00\x00\x00\x00\x00\x01\x00\x00"
	. "\x00\x1a\x69\x6e\x66\x65\x02\x00\x00\x00\x00\x01\x00\x00\x61\x76"
	. "\x30\x31\x43\x6f\x6c\x6f\x72\x00\x00\x00\x00\x6a\x69\x70\x72\x70"
	. "\x00\x00\x00\x4b\x69\x70\x63\x6f\x00\x00\x00\x14\x69\x73\x70\x65"
	. "\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x06\x00\x00\x00\x10"
	. "\x70\x69\x78\x69\x00\x00\x00\x00\x03\x08\x08\x08\x00\x00\x00\x0c"
	. "\x61\x76\x31\x43\x81\x00\x0c\x00\x00\x00\x00\x13\x63\x6f\x6c\x72"
	. "\x6e\x63\x6c\x78\x00\x01\x00\x0d\x00\x01\x80\x00\x00\x00\x17\x69"
	. "\x70\x6d\x61\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x04\x01\x02"
	. "\x83\x04\x00\x00\x00\x58\x6d\x64\x61\x74\x12\x00\x0a\x08\x18\x0c"
	. "\xa6\xb0\x40\x43\x40\x61\x32\x42\x13\x40\x02\x08\x20\x85\x00\xc9"
	. "\xd0\x69\xb9\x45\x9c\x7a\x42\x42\xae\xdc\x3c\xe4\xfe\x3c\xa3\xb5"
	. "\x50\x93\x1f\x12\x1e\xa0\xac\xb4\xfa\xfc\xe6\xab\x12\x14\xcc\x64"
	. "\xc6\x1b\xe5\x3d\x6f\x96\xae\x1a\x23\xb7\x19\x45\x1c\xe4\xe4\xb3"
	. "\x3e\xa6\x72\xa0\x9b\x36\xb7\x10\xd0\xe8");

# iprp_ipco.avif
# 00000000: 0000 0020 6674 7970 6176 6966 0000 0000  ... ftypavif....
# 00000010: 6176 6966 6d69 6631 6d69 6166 4d41 3142  avifmif1miafMA1B
# 00000020: 0000 00f2 6d65 7461 0000 0000 0000 0028  ....meta.......(
# 00000030: 6864 6c72 0000 0000 0000 0000 7069 6374  hdlr........pict
# 00000040: 0000 0000 0000 0000 0000 0000 6c69 6261  ............liba
# 00000050: 7669 6600 0000 000e 7069 746d 0000 0000  vif.....pitm....
# 00000060: 0001 0000 001e 696c 6f63 0000 0000 4400  ......iloc....D.
# 00000070: 0001 0001 0000 0001 0000 011a 0000 0058  ...............X
# 00000080: 0000 0028 6969 6e66 0000 0000 0001 0000  ...(iinf........
# 00000090: 001a 696e 6665 0200 0000 0001 0000 6176  ..infe........av
# 000000a0: 3031 436f 6c6f 7200 0000 006a 6970 7270  01Color....jiprp
# 000000b0: 0000 004b 6970 636f 0000 0014 6973 7065  ...Kipco....ispe
# 000000c0: 0000 0000 0000 000a 0000 0007 0000 0010  ................
# 000000d0: 7069 7869 0000 0000 0308 0808 0000 000c  pixi............
# 000000e0: 6176 3143 8100 0c00 0000 0013 636f 6c72  av1C........colr
# 000000f0: 6e63 6c78 0001 000d 0001 8000 0000 1769  nclx...........i
# 00000100: 706d 6100 0000 0000 0000 0100 0104 0102  pma.............
# 00000110: 8304 0000 0060 6d64 6174 1200 0a08 180c  .....`mdat......
# 00000120: a730 4043 4061 324a 1340 0208 2084 00c0  .0@C@a2J.@.. ...
# 00000130: df02 397d ef93 a025 392f b8f0 89e9 d9ad  ..9}...%9/......
# 00000140: c462 e3b7 5e7a 6a42 6475 a4f1 47d2 09f8  .b..^zjBdu..G...
# 00000150: 3f2c 06fe 7e25 c865 ec26 3b3c d7c2 ff85  ?,..~%.e.&;<....
# 00000160: a94a 2a6c d927 d367 bf9e f5e4 da76 4720  .J*l.'.g.....vG
# 00000170: 0eac                                     ..

$t->write_file('iprp_ipco.avif',
	  "\x00\x00\x00\x20\x66\x74\x79\x70\x61\x76\x69\x66\x00\x00\x00\x00"
	. "\x61\x76\x69\x66\x6d\x69\x66\x31\x6d\x69\x61\x66\x4d\x41\x31\x42"
	. "\x00\x00\x00\xf2\x6d\x65\x74\x61\x00\x00\x00\x00\x00\x00\x00\x28"
	. "\x68\x64\x6c\x72\x00\x00\x00\x00\x00\x00\x00\x00\x70\x69\x63\x74"
	. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6c\x69\x62\x61"
	. "\x76\x69\x66\x00\x00\x00\x00\x0e\x70\x69\x74\x6d\x00\x00\x00\x00"
	. "\x00\x01\x00\x00\x00\x1e\x69\x6c\x6f\x63\x00\x00\x00\x00\x44\x00"
	. "\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x01\x1a\x00\x00\x00\x58"
	. "\x00\x00\x00\x28\x69\x69\x6e\x66\x00\x00\x00\x00\x00\x01\x00\x00"
	. "\x00\x1a\x69\x6e\x66\x65\x02\x00\x00\x00\x00\x01\x00\x00\x61\x76"
	. "\x30\x31\x43\x6f\x6c\x6f\x72\x00\x00\x00\x00\x6a\x69\x70\x72\x70"
	. "\x00\x00\x00\x4b\x69\x70\x63\x6f\x00\x00\x00\x14\x69\x73\x70\x65"
	. "\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x07\x00\x00\x00\x10"
	. "\x70\x69\x78\x69\x00\x00\x00\x00\x03\x08\x08\x08\x00\x00\x00\x0c"
	. "\x61\x76\x31\x43\x81\x00\x0c\x00\x00\x00\x00\x13\x63\x6f\x6c\x72"
	. "\x6e\x63\x6c\x78\x00\x01\x00\x0d\x00\x01\x80\x00\x00\x00\x17\x69"
	. "\x70\x6d\x61\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x04\x01\x02"
	. "\x83\x04\x00\x00\x00\x60\x6d\x64\x61\x74\x12\x00\x0a\x08\x18\x0c"
	. "\xa7\x30\x40\x43\x40\x61\x32\x4a\x13\x40\x02\x08\x20\x84\x00\xc0"
	. "\xdf\x02\x39\x7d\xef\x93\xa0\x25\x39\x2f\xb8\xf0\x89\xe9\xd9\xad"
	. "\xc4\x62\xe3\xb7\x5e\x7a\x6a\x42\x64\x75\xa4\xf1\x47\xd2\x09\xf8"
	. "\x3f\x2c\x06\xfe\x7e\x25\xc8\x65\xec\x26\x3b\x3c\xd7\xc2\xff\x85"
	. "\xa9\x4a\x2a\x6c\xd9\x27\xd3\x67\xbf\x9e\xf5\xe4\xda\x76\x47\x20"
	. "\x0e\xac");

# iprp_ipco.heic
# 00000000: 0000 001c 6674 7970 6865 6978 0000 0000  ....ftypheix....
# 00000010: 6d69 6631 6865 6978 6d69 6166 0000 0259  mif1heixmiaf...Y
# 00000020: 6d65 7461 0000 0000 0000 0021 6864 6c72  meta.......!hdlr
# 00000030: 0000 0000 0000 0000 7069 6374 0000 0000  ........pict....
# 00000040: 0000 0000 0000 0000 0000 0000 0e70 6974  .............pit
# 00000050: 6d00 0000 0000 0100 0000 3469 6c6f 6300  m.........4iloc.
# 00000060: 0000 0044 4000 0200 0100 0000 0002 7d00  ...D@.........}.
# 00000070: 0100 0000 0000 0001 0100 0200 0000 0003  ................
# 00000080: 7e00 0100 0000 0000 0000 2400 0000 3869  ~.........$...8i
# 00000090: 696e 6600 0000 0000 0200 0000 1569 6e66  inf..........inf
# 000000a0: 6502 0000 0000 0100 0068 7663 3100 0000  e........hvc1...
# 000000b0: 0015 696e 6665 0200 0000 0002 0000 6876  ..infe........hv
# 000000c0: 6331 0000 0001 9869 7072 7000 0001 7169  c1.....iprp...qi
# 000000d0: 7063 6f00 0000 7768 7663 4301 0408 0000  pco...whvcC.....
# 000000e0: 0000 0000 0000 001e f000 fcff f8f8 0000  ................
# 000000f0: 0f03 6000 0100 1740 010c 01ff ff04 0800  ..`....@........
# 00000100: 0003 009e 3800 0003 0000 1eba 0240 6100  ....8........@a.
# 00000110: 0100 2a42 0101 0408 0000 0300 9e38 0000  ..*B.........8..
# 00000120: 0300 001e 9004 1020 b2dd 55d3 5cdc 0434  ....... ..U.\..4
# 00000130: 1810 0000 0300 1000 0003 0010 8062 0001  .............b..
# 00000140: 0008 4401 c173 1830 1890 0000 0014 6973  ..D..s.0......is
# 00000150: 7065 0000 0000 0000 0040 0000 0040 0000  pe.......@...@..
# 00000160: 0028 636c 6170 0000 000a 0000 0001 0000  .(clap..........
# 00000170: 0006 0000 0001 ffff ffca 0000 0002 ffff  ................
# 00000180: ffc6 0000 0002 0000 0010 7069 7869 0000  ..........pixi..
# 00000190: 0000 0308 0808 0000 0071 6876 6343 0104  .........qhvcC..
# 000001a0: 0800 0000 0000 0000 0000 1ef0 00fc fcf8  ................
# 000001b0: f800 000f 0360 0001 0017 4001 0c01 ffff  .....`....@.....
# 000001c0: 0408 0000 0300 9ff8 0000 0300 001e ba02  ................
# 000001d0: 4061 0001 0026 4201 0104 0800 0003 009f  @a...&B.........
# 000001e0: f800 0003 0000 1ec0 8204 165b aaba 6b9b  ...........[..k.
# 000001f0: 0200 0003 0002 0000 0300 0210 6200 0100  ............b...
# 00000200: 0644 01c1 73c1 8900 0000 0e70 6978 6900  .D..s......pixi.
# 00000210: 0000 0001 0800 0000 2761 7578 4300 0000  ........'auxC...
# 00000220: 0075 726e 3a6d 7065 673a 6865 7663 3a32  .urn:mpeg:hevc:2
# 00000230: 3031 353a 6175 7869 643a 3100 0000 001f  015:auxid:1.....
# 00000240: 6970 6d61 0000 0000 0000 0002 0001 0481  ipma............
# 00000250: 0204 8300 0205 8502 0687 8300 0000 1a69  ...............i
# 00000260: 7265 6600 0000 0000 0000 0e61 7578 6c00  ref........auxl.
# 00000270: 0200 0100 0100 0001 2d6d 6461 7400 0000  ........-mdat...
# 00000280: fd28 01af 04f2 088f 2d0b 802d 1ce2 a239  .(......-..-...9
# 00000290: ac80 fbdf 815b 0c12 409f c757 3e7a 3479  .....[..@..W>z4y
# 000002a0: a46a da93 292b 87ef 48bd 6c0f 3065 792e  .j..)+..H.l.0ey.
# 000002b0: b06a 54be da59 73a9 35d7 cd33 181e d40b  .jT..Ys.5..3....
# 000002c0: cada d00c 821f d35b e79e 54bf d5da a157  .......[..T....W
# 000002d0: 8493 f918 0c8f 3374 0c3a c7df 6780 cb13  ......3t.:..g...
# 000002e0: 784f 5b90 37c8 2a84 b3be 4fd9 5459 1035  xO[.7.*...O.TY.5
# 000002f0: 1c66 997d 8f3a 1547 c9ec ff95 6d7f 8b94  .f.}.:.G....m...
# 00000300: cb23 19f5 aaf9 e676 68ea 20e3 0bc4 4075  .#.....vh. ...@u
# 00000310: 47fe 4ddf 8bda 2de8 402f e8a5 b6d9 3e09  G.M...-.@/....>.
# 00000320: 066d 9266 0210 433c f702 5f29 10b2 174b  .m.f..C<.._)...K
# 00000330: b6a6 880a f191 64f2 1ffd 4125 36e2 5d04  ......d...A%6.].
# 00000340: 3e05 ecc7 dd25 7fd7 f45e 79ad 4702 b5cf  >....%...^y.G...
# 00000350: 54d1 b72f ecaf 32be 1e69 45d0 c53d a5d5  T../..2..iE..=..
# 00000360: 15b0 cfb7 b572 d5f5 9f03 36a3 a122 0ea5  .....r....6.."..
# 00000370: b4cc a9a8 43fd bb4c 7bcc a37f 1a1c 0000  ....C..L{.......
# 00000380: 0020 2801 ae09 e424 a240 9fe9 92ff f4ae  . (....$.@......
# 00000390: 6aa1 f195 711c e173 f478 f1de ad40 359d  j...q..s.x...@5.
# 000003a0: 273a                                     ':

$t->write_file('iprp_ipco.heic',
	  "\x00\x00\x00\x1c\x66\x74\x79\x70\x68\x65\x69\x78\x00\x00\x00\x00"
	. "\x6d\x69\x66\x31\x68\x65\x69\x78\x6d\x69\x61\x66\x00\x00\x02\x59"
	. "\x6d\x65\x74\x61\x00\x00\x00\x00\x00\x00\x00\x21\x68\x64\x6c\x72"
	. "\x00\x00\x00\x00\x00\x00\x00\x00\x70\x69\x63\x74\x00\x00\x00\x00"
	. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x70\x69\x74"
	. "\x6d\x00\x00\x00\x00\x00\x01\x00\x00\x00\x34\x69\x6c\x6f\x63\x00"
	. "\x00\x00\x00\x44\x40\x00\x02\x00\x01\x00\x00\x00\x00\x02\x7d\x00"
	. "\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x02\x00\x00\x00\x00\x03"
	. "\x7e\x00\x01\x00\x00\x00\x00\x00\x00\x00\x24\x00\x00\x00\x38\x69"
	. "\x69\x6e\x66\x00\x00\x00\x00\x00\x02\x00\x00\x00\x15\x69\x6e\x66"
	. "\x65\x02\x00\x00\x00\x00\x01\x00\x00\x68\x76\x63\x31\x00\x00\x00"
	. "\x00\x15\x69\x6e\x66\x65\x02\x00\x00\x00\x00\x02\x00\x00\x68\x76"
	. "\x63\x31\x00\x00\x00\x01\x98\x69\x70\x72\x70\x00\x00\x01\x71\x69"
	. "\x70\x63\x6f\x00\x00\x00\x77\x68\x76\x63\x43\x01\x04\x08\x00\x00"
	. "\x00\x00\x00\x00\x00\x00\x00\x1e\xf0\x00\xfc\xff\xf8\xf8\x00\x00"
	. "\x0f\x03\x60\x00\x01\x00\x17\x40\x01\x0c\x01\xff\xff\x04\x08\x00"
	. "\x00\x03\x00\x9e\x38\x00\x00\x03\x00\x00\x1e\xba\x02\x40\x61\x00"
	. "\x01\x00\x2a\x42\x01\x01\x04\x08\x00\x00\x03\x00\x9e\x38\x00\x00"
	. "\x03\x00\x00\x1e\x90\x04\x10\x20\xb2\xdd\x55\xd3\x5c\xdc\x04\x34"
	. "\x18\x10\x00\x00\x03\x00\x10\x00\x00\x03\x00\x10\x80\x62\x00\x01"
	. "\x00\x08\x44\x01\xc1\x73\x18\x30\x18\x90\x00\x00\x00\x14\x69\x73"
	. "\x70\x65\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00"
	. "\x00\x28\x63\x6c\x61\x70\x00\x00\x00\x0a\x00\x00\x00\x01\x00\x00"
	. "\x00\x06\x00\x00\x00\x01\xff\xff\xff\xca\x00\x00\x00\x02\xff\xff"
	. "\xff\xc6\x00\x00\x00\x02\x00\x00\x00\x10\x70\x69\x78\x69\x00\x00"
	. "\x00\x00\x03\x08\x08\x08\x00\x00\x00\x71\x68\x76\x63\x43\x01\x04"
	. "\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\xf0\x00\xfc\xfc\xf8"
	. "\xf8\x00\x00\x0f\x03\x60\x00\x01\x00\x17\x40\x01\x0c\x01\xff\xff"
	. "\x04\x08\x00\x00\x03\x00\x9f\xf8\x00\x00\x03\x00\x00\x1e\xba\x02"
	. "\x40\x61\x00\x01\x00\x26\x42\x01\x01\x04\x08\x00\x00\x03\x00\x9f"
	. "\xf8\x00\x00\x03\x00\x00\x1e\xc0\x82\x04\x16\x5b\xaa\xba\x6b\x9b"
	. "\x02\x00\x00\x03\x00\x02\x00\x00\x03\x00\x02\x10\x62\x00\x01\x00"
	. "\x06\x44\x01\xc1\x73\xc1\x89\x00\x00\x00\x0e\x70\x69\x78\x69\x00"
	. "\x00\x00\x00\x01\x08\x00\x00\x00\x27\x61\x75\x78\x43\x00\x00\x00"
	. "\x00\x75\x72\x6e\x3a\x6d\x70\x65\x67\x3a\x68\x65\x76\x63\x3a\x32"
	. "\x30\x31\x35\x3a\x61\x75\x78\x69\x64\x3a\x31\x00\x00\x00\x00\x1f"
	. "\x69\x70\x6d\x61\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x04\x81"
	. "\x02\x04\x83\x00\x02\x05\x85\x02\x06\x87\x83\x00\x00\x00\x1a\x69"
	. "\x72\x65\x66\x00\x00\x00\x00\x00\x00\x00\x0e\x61\x75\x78\x6c\x00"
	. "\x02\x00\x01\x00\x01\x00\x00\x01\x2d\x6d\x64\x61\x74\x00\x00\x00"
	. "\xfd\x28\x01\xaf\x04\xf2\x08\x8f\x2d\x0b\x80\x2d\x1c\xe2\xa2\x39"
	. "\xac\x80\xfb\xdf\x81\x5b\x0c\x12\x40\x9f\xc7\x57\x3e\x7a\x34\x79"
	. "\xa4\x6a\xda\x93\x29\x2b\x87\xef\x48\xbd\x6c\x0f\x30\x65\x79\x2e"
	. "\xb0\x6a\x54\xbe\xda\x59\x73\xa9\x35\xd7\xcd\x33\x18\x1e\xd4\x0b"
	. "\xca\xda\xd0\x0c\x82\x1f\xd3\x5b\xe7\x9e\x54\xbf\xd5\xda\xa1\x57"
	. "\x84\x93\xf9\x18\x0c\x8f\x33\x74\x0c\x3a\xc7\xdf\x67\x80\xcb\x13"
	. "\x78\x4f\x5b\x90\x37\xc8\x2a\x84\xb3\xbe\x4f\xd9\x54\x59\x10\x35"
	. "\x1c\x66\x99\x7d\x8f\x3a\x15\x47\xc9\xec\xff\x95\x6d\x7f\x8b\x94"
	. "\xcb\x23\x19\xf5\xaa\xf9\xe6\x76\x68\xea\x20\xe3\x0b\xc4\x40\x75"
	. "\x47\xfe\x4d\xdf\x8b\xda\x2d\xe8\x40\x2f\xe8\xa5\xb6\xd9\x3e\x09"
	. "\x06\x6d\x92\x66\x02\x10\x43\x3c\xf7\x02\x5f\x29\x10\xb2\x17\x4b"
	. "\xb6\xa6\x88\x0a\xf1\x91\x64\xf2\x1f\xfd\x41\x25\x36\xe2\x5d\x04"
	. "\x3e\x05\xec\xc7\xdd\x25\x7f\xd7\xf4\x5e\x79\xad\x47\x02\xb5\xcf"
	. "\x54\xd1\xb7\x2f\xec\xaf\x32\xbe\x1e\x69\x45\xd0\xc5\x3d\xa5\xd5"
	. "\x15\xb0\xcf\xb7\xb5\x72\xd5\xf5\x9f\x03\x36\xa3\xa1\x22\x0e\xa5"
	. "\xb4\xcc\xa9\xa8\x43\xfd\xbb\x4c\x7b\xcc\xa3\x7f\x1a\x1c\x00\x00"
	. "\x00\x20\x28\x01\xae\x09\xe4\x24\xa2\x40\x9f\xe9\x92\xff\xf4\xae"
	. "\x6a\xa1\xf1\x95\x71\x1c\xe1\x73\xf4\x78\xf1\xde\xad\x40\x35\x9d"
	. "\x27\x3a");

# TODO: files with extended length

$t->run()->plan(30);

###############################################################################

SKIP: {
	skip 'AVIF is not supported', 20
		if !format_supported('/resize/simple.avif');

	check_path('/test/simple.avif');
	check_path('/test/iprp_ipco.avif');
	check_size('simple.avif', 10, 6);
	check_size('iprp_ipco.avif', 10, 7);

	check_path('/resize/simple.avif');
	check_path('/avif_quality/simple.avif');
	check_path('/avif_quality_var/simple.avif?q=20&s=2');

	check_path('/resize/iprp_ipco.avif');
	check_path('/avif_quality/iprp_ipco.avif');
	check_path('/avif_quality_var/simple.avif?q=30&s=3');
}

SKIP: {
	skip 'HEIC is not supported', 10
		if rosa13_broken_x265() || !format_supported('/resize/iprp_ipco.heic');

	check_path('/test/iprp_ipco.heic');
	check_size('iprp_ipco.heic', 64, 64);

	check_path('/resize/iprp_ipco.heic');
	check_path('/heic_quality/iprp_ipco.heic');
	check_path('/heic_quality_var/iprp_ipco.heic?q=40');
}

###############################################################################

sub check_size {
	my ($file, $width, $height) = @_;

	my $j = get_json("/size/$file");

	is($j->{img}{width}, $width, "width $file");
	is($j->{img}{height}, $height, "height $file");
}

sub get_file_format {
	my ($file) = @_;

	if ($file =~ /\.([a-z0-9]{1,8})(?:\?|$)/i) {
		return lc($1);
	}

	return undef;
}

sub check_path {
	my ($file) = @_;

	my $format = get_file_format($file);
	my $r = http_get($file);

	like($r, qr/200 OK/, $file);
	like($r, qr!Content-Type: image/$format!, "content-type $file");
}

sub format_supported {
	my ($file) = @_;

	my $r = http_get($file);

	return !($r =~ qr/415/);
}

sub rosa13_broken_x265 {
	open(my $fh, '<', '/etc/os-release') or return 0;
	my $data = do { local $/; <$fh> };
	close($fh);

	my $id = ($data =~ /^ID=(\w+)/m) ? $1 : '';
	my $version = ($data =~ /^VERSION_ID=(\S+)/m) ? $1 : '';

	if ($id ne 'rosa' || $version ne 13) {
		return 0;
	}

	return (-e '/usr/lib64/libx265.so.212') ? 1 : 0;
}
