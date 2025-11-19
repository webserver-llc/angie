#!/usr/bin/perl

# (C) 2025 Web Server LLC

# ACME test obtaining a certificate for a large number of domains

# This script requires pebble and pebble-challtestsrv
# (see Test::Nginx::ACME for details)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::ACME;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'long test') unless $ENV{TEST_ANGIE_UNSAFE};

my $t = Test::Nginx->new()->has(qw/acme http_ssl socket_ssl/);

# XXX
# We don't use the port function here, because the port it creates is currently
# incompatible with challtestsrv (they both create a pair of tcp/udp sockets on
# the same port number, which eventually results in challtestsrv getting an
# "Address already in use" error).
# While it is not entirely safe to use this port number, this shouldn't cause
# problems in most cases.
my $dns_port = 19053;

my $acme_helper = Test::Nginx::ACME->new({t => $t, dns_port => $dns_port});

my $pebble_port = port(14000);
my $http_port = port(5002);

# Let's Encrypt currently allows no more than 100 domain names per certificate.
my @domains;

while (<DATA>) {
	chomp;
	push @domains, $_;
}

my $server_name = '';

for my $s (@domains) {
	$server_name .= "            $s\n";
}

$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%

worker_processes auto;
daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver localhost:$dns_port ipv6=off;

    acme_client test https://localhost:$pebble_port/dir
                email=admin\@angie-test.com;

    server {
        listen               %%PORT_8443%% ssl;
        server_name
$server_name
        ;

        ssl_certificate      \$acme_cert_test;
        ssl_certificate_key  \$acme_cert_key_test;

        acme                 test;

        location / {
            return           200 "SECURED";
        }
    }

    acme_http_port $http_port;
}

EOF

$acme_helper->start_challtestsrv();

$acme_helper->start_pebble({
	pebble_port => $pebble_port, http_port => $http_port,
	certificate_validity_period => 10
});

$t->try_run('variables in "ssl_certificate" and "ssl_certificate_key" '
	. 'directives are not supported on this platform');

$t->plan(2);

my $cert_file = $t->testdir() . '/acme_client/test/certificate.pem';

# First, obtain the certificate.

my $obtained = 0;

for (1 .. 15 * 60) {
	$obtained = -s $cert_file;
	last if $obtained;

	select undef, undef, undef, 1;
}

ok($obtained, 'obtained certificate');

# Then try to use it.

my $used = 1;

for my $domain (@domains) {
	my $s = http(<<EOF, SSL => 1);
POST / HTTP/1.0
Host: $domain

EOF

	$s = http_content($s);

	if ($s ne 'SECURED') {
		$used = 0;
		last;
	}
}

ok($used, 'used certificate');

__DATA__
dv9lm70zwspkz58if.e5t6qzv9.angie-test1.com
oi35sj39oakwhx8rfuwnascuynxd0yo56r07it.3x3wo2fe4oy5u0u3zx7d5dzw102igouna0nwyurb9he6i59nd3.cyecveviunnlpvhhdtp.angie-test2.com
tsmf73gw3ngc6u6guypd82xge5g094fzwnx4jzexsq2swk2w.3qq6wegujost.angie-test3.com
ib7ihwghhxcn5b1icvdxkq2afol4nqlt7ulqgo2mdet2dny7u.mnshsawnhldvbyjt8mdiyt05avqefge3qvu.angie-test4.com
sy45aktw4hcmwgzn5wb9s68tb3r6yjgyjkqzg74gyjz.rhy72zjr9o2gg9e4pdw8dqemawklwo7ezix6jqou87m963.ifetxffgkb36x49iio2zltn5nvkg17foh98288o1p1vrzuuoknvlb8cfxmqf.angie-test5.com
id0iz8mfh0rsl1.yp3v1mz8uxul2pqhspa922pojx21qh657ckatymrojruxiy9rgh.angie-test6.com
ooztjsjgx6xle64f4io1s2ca8137o42l6pvqk7l6n0.ofyevvmv.iu98rhni981odr3yz4k26xmtyd5s9gccw4l0vq01atlx5d9asvy8vhhiunt.angie-test7.com
ixlpz3cooacs873nkyo3yn5.nv59orqvkfkxuayu0balh2s47abmfaea1jnabm212.angie-test8.com
bolxevvp24.ram08jvvs9frp6ly.angie-test9.com
nueqv8ndiwkjcnqhjshb2n3szs5ady924eub7v.2oljlh0uz0t9d4v2xx.angie-test10.com
cun0w3zd0vmdaz6fjdbvm1gfah98sxw9ei58j62m5.6o6il65b71k1guoqwsamopla50zn2bjlgqdrut5wquls.angie-test11.com
dpyq961iebz7btwweix.vzxnq.angie-test12.com
e2mncf0qatbf.drs1rd7r7ht5kp7tvxa9ax22xx54q5jq0nkowp064ba3arq.angie-test13.com
8g6vnxs8ja9insjsy8q1v.o91dvn.angie-test14.com
ywpd9rv2q7xgia514n62b.jz320uathlvhyvpa8ysmepij7pf249n3o1dyk7lxt.angie-test15.com
xfsl053sgmsnmrz5k0cwzoemgo18fb35otlkcpu3r100.pixhsgy7e4z9ylsk0bq1dvmab0mn19ca87lozvg8yvqzdvpqm1yy0271b2m.angie-test16.com
uilfizxepvlv4s3.rbbugnmhvadawlo5imr7ztdk28fpbdsh61r9h066w2.8bv901a0n6imrs.angie-test17.com
ytauwi63stlvi5rz40wc73nqhk313x1g3bhv8idi322ktk.dlloenjmsvd9c.i5sba1lp33u5aw9c0x1svxr4twaedvrdd.angie-test18.com
sj0bbuugujyj7bs8ulc6d1o5rbwtrb6yn1b8.okh1q2zwci5vrrgz4z0w5ge5bu1o75xxfgpilt6nukvuyd03o3h9kk14aqnb.ycpm5ooikmhsf8tniiko1pxz64qc91gus3ddpdmm53euk4xwdsyys90tnz78.angie-test19.com
47f3i8m4rj4626obpbo8zig9f7mzq8stq8j2eotv30guwp7cwb1mfgg3no.xp194phi6d84xnct03.a0v6h2.angie-test20.com
ti0yslepqhw.d5gxflyi1251htp2kdjy21isosg.angie-test21.com
9uhf4sfsjfnu.ano3vka03uwwgwdmsacs8nhzfr0coe9x7hm34h621c5.j42a4zota05.angie-test22.com
jop4wh44nm7hk8zr9986bbf8jc.zlony1mgg1ox15uj5csvb.kpsossp74che22jsos95q79wjlx19y3s70exa1pg.angie-test23.com
spplb92pdd8q8zgra2kn5gehsl.6h30jjtrl8up9v2emlctciimbzuyvaq29kbcqwrh0mkt.39hi7rgpf2lhou.angie-test24.com
uw0tw.7pdqmqhhcqxhjmk97rh8bbw.angie-test25.com
apitomzcq2iadw8dam4kr8pj3c1uez7hl2i5bw.bzxmypajv13trv9s50is6ec8hcgjhnlz9na2h8s8hlh9hbwcw91z.trbbeze99idoh81fvvkvgw8iqf245vfspvz2tbsj3ri.angie-test26.com
em7k7ldooy4g3kixos9clf7tpkf2mp.g2ggt9w.angie-test27.com
5i4di5r2hgtw5x2ez5rv14swhxoz082qbgkd9ljz6qd24b3f0by.pms74ioguzo8kc1qe63l5ohtu3qbkmvqbf5tsy5vxqgtqgp7myfhg.mdqqnjof20x.angie-test28.com
kfsu72v158c8xkaeovetdh7hkn0gqz3pxcobiycwj.m6w6qb23d04.angie-test29.com
4224xy.u226t3w4xu4a1vh5gzhjm1qhujmrlwy01o0ae47cfv0zvt9w8kr.w8ndsanlbnaqjywe16qi3ul4ul6u5h.angie-test30.com
1uj8zbkcp0ii057obagw7ivzkef8pvd6pu8pphytp39l6.rgk4u6xuqj4876p1imws3scn7k07ac021nwl99mb57abg8oqzdwimibdwfo.angie-test31.com
db4pgvt5nx8mbrll2ymsu4.3dkd43g2yprbw7996qezhhp1pg03ztx5tjq95ryduqnf.nwr75yuta28r4krytcx9s2i884wwkel9d7l.angie-test32.com
58995swu6ig7n0wjvsb0pduanb5ah6tj.e69ppflk2woj.r8fb1o8940e0tesydpn3q02brkuqmjeotg51wc.angie-test33.com
jh6sa036mad9sd6ycpfz2yuaigkqjs5o68irpydnmz7j4dcy8.uf7qp.angie-test34.com
jnwbz3m5w4tt51wveli51srryc0vljap01.orn4e7dm9z16x2b0mznsg007rya1ac9i3ng5woy8d30e.qjhsnos96e2yvykg.angie-test35.com
a2z6zmat8d2u6.5q6vdd0hkt6fbfy8v9l5t4m4zqznekdh5hu8gczrl0h.angie-test36.com
8pfsr8kxbv5n7xdxot3kua2k2s01t9m4fjkk7pqyskjt.ul35t9ih2foln1cupq4xxmdrg1c01vgsp3n1gamv587dthh562ppbooml6.angie-test37.com
23bxd04rul945g4dwq3dki64iz3bk19w0mlw3mt1ub2mzkjuhagc90z.kvd6dkwnagppn2cb8dyctz1k1zjv3h87185q4xdoswe1la96l.angie-test38.com
tcnoxy1h18se7oaa6r1ti0g2la4exiyzogq.spkjdxkw6clz9v1slkf8stohr8f2nfm9swrqydopobjn4j2.angie-test39.com
y6vn1nk5hge.vjgfcl40zgnze93i627y0t5bqsse43j5e40wah80w589vao36facahi43s.angie-test40.com
gnxwgbue8imrn1ymer7bu1sdncuzxer1p5gtkfnb21kuho8f.mkvhczac6klv09m1rb4owkvji19akce5al09nd52g27hytwizjurouut9r.uzlgnl3l.angie-test41.com
heor2n56vk9ff16c.vu9bck2ol3u1jtott1tl1gbzt13reakwmtmwrc0wbjhig64ud5dyid0is415.iyavsiwjhyq.angie-test42.com
f4z1jwvi8sw39lpa5zpd985ete12w155iej3wszlkyhx3zba5qp.s0ml2itnctou91.x2me5cu69y3bjoz.angie-test43.com
yyba70457c70vj8e4hjb8zk1atv6khee6wwk537n8i4f4r.9x63sk.angie-test44.com
7b0f41m1wmu5zjgxw0w5le038w8mje8b.0lzyu5rwq4r8lp75p.75gb3glphg0z5ysa04pqkxrr71xyvcxquy02vaqn23xmj19e4i6ohw3.angie-test45.com
31sy1a7vvtpzocxod5onxblec2h3o9i07x7wohsgpae6p1w36.6ionpt9580uctsc0uj2rfx4mm44c503z5kz5k4u5t9fnu96.vqdithyv49mdvbiqd8g3c22dm9cg.angie-test46.com
ldv61x1b1ix0t9yipejy5fc7im1maunoy7.daykc15sopu0ns5jz2.uzjs2w2xys7gwup9oqvjjxzitvlux1znsxb8kucts0dy26wx.angie-test47.com
jz7y549kn9g5w.tjs9lvp3cqd1zpttqx08xpyhlsl397zeuwjs63tfwefrj.angie-test48.com
440ymyyw.rcejhi1inqmhv73hcgku1et3za498vxa2znhx18iina82uoqj1lqy.angie-test49.com
6wz6dvrbq64ucbnobqu2p7c4c79l7cjx9r14bd0sxf0a2xxrt9w1g.yemzuovj7451q54csgegdedf185lhpnsax5vf4mj.angie-test50.com
ahiq9gle5yssy7x7d273qknhiz3w05assy7nijhd0t6ni.lr52jhyw46lyruydkrz66s2nn597lfdp49owc5lvvhdhg7rayhlfr7wrt.angie-test51.com
00aggpogo2afalnmrk72eagp6vew.9cbpl5w6jjv94zkx9wi2mbzkxk43lexm.hhupk6ufpnpuvlk81sqmhxpz1sabvjza.angie-test52.com
nrgoj8w59gshnd5n1iqegc8kko6bpsz7.135a0tvvncwswcwwys1gz7y793ekte6yo1wn7noe.bf6nbfpnenfr09kpjj.angie-test53.com
ziln07xd4fdk0h09iazc24ujvy4fpsxyv9w5mcuzbmwxjkcs78u.4fvqn52fwyyical7dscvq67zne307t5y.angie-test54.com
gb66hrx4uxmq.bzks8j5x665nkbobl.angie-test55.com
sadcr720toj.fp9xixslvipdg1yqim658.angie-test56.com
xrwwz5f9ky2b0vaqkig1rta6hzgaasyzr6hnd1dapt9ap3kplf210cy.dh5fh8xytfk0ic74hoqz51ipluqc2qio3grdtngaq.angie-test57.com
tmdfb1djavr9o1lxahko19kgyrcd4bmn0j36s8jujyf4x5440rl8a5b4g4c2.8rcf2zyyieieiztls.angie-test58.com
0u8175i3rjzzgo8mh0oupt0n4wenffwl09lu.psgyqj93nukptjxwssklo1.angie-test59.com
qjmjb0ber6ruzyfb9s23rt1b8tuiwog38k7smdmw7j.d9kpbwh8k92.angie-test60.com
9i8d2xd9h1ylrs2729n488pit6c4tt6zj9f4blpgc3g.9txieuk4mkelgx2ye29zgq.8ndscqp04gmg5y6edkmcxu8hxgjvfxq466w3xapsfasp21jb.angie-test61.com
vwd2sv8v3km17gba82lldenrrot2z90xj3g42hrx.gsu3tebrrq7d8sqewsno6c.angie-test62.com
dc3bauu4qtosiuc94c90cj05kzxvlx1h623fy1bnmeipxgawkf4.reawyk60z1q5cwtdiqtaz20ols.gij1clz0uffj2s47xk5v6e0jcx0un7rcy9r0b24jid5oliflz9u4f.angie-test63.com
czkmx5wn1zwdtnaa.clhzpf4k453nspa2o7kt6x0tk6fexo23l50zgekgyeozsqd3u812.nzu21dqswxy.angie-test64.com
ro7j4rgipfub9sml70vdyha2gotrylrm3yjxkg66v68nsblv4s.1kcwt0b8ywwwxos0h6oqsd8gb9hrpng1125o.angie-test65.com
skp38be14rzelj0txoftpr6u8ubzo1dtd3cpx52wo58zqcfo.h9nwlhj2wgwm4h2pc9w620lrpp2jyp60fkmb1o9p8cc17fxz5mb.angie-test66.com
a33cqeqnrnvn5oc4ob9t55o9wgtohn.c6m32s.angie-test67.com
yxd7xuopilje9l3p4rxlqx76ds52mqur3i0r.4act4va8i0qn2.angie-test68.com
1kmuhgn1qp.qivrc84nlvh3panru095t9zp5fmegvhfyczy7bji1cq2.angie-test69.com
fccd8484.lro0zkl11hg8zpcf8uo7hn0bqjhe8zs5j6pmlhy3g4u.angie-test70.com
q0q1ta41znc5uwre60bo.hnpxtdd837j7x2os0odglfjr7r.8lkpedagh65qahtw847zc9rwd9vks5qk7dznoxejlldjz.angie-test71.com
qayod2q0vrg0426kcc73ai0ksy7bisheuudpuowg3sjyduw6azwz0y1sqrk5.780ctuoqle7bjde2v4q5.cq4ijjwwpjwzaeol.angie-test72.com
9nilkalyu6dkzekr21z8t16am2wzoprf6omc7p2owop96j7csznst1iyxtce.i94r5dcorjhxnztxvr0lq4y0yf8sfu7m6z.angie-test73.com
6x862k8672nh7.lbm33i.angie-test74.com
364y9fahh8ahny1a8wurxhjdpos270kh93at1q45pn0e0a7z4qwlenks4.ry27j4r85q0snox1mqlpc754mt29f7ut3fncp.angie-test75.com
kq5afkf90z0lkqbg9mpyytox.lb7kao4z784omd9apq11b7f35xhl1jwq0l308ltxn6kr8.angie-test76.com
3w0zp91p.pm27x5xfia.angie-test77.com
3vx5ahdflena.r4dguejjzpp07uy1g2jrkf.angie-test78.com
0ifeaka2ulfmafq9u1drneg5d7dc4gpp946n9cyr1x.lm974137u43.angie-test79.com
f1mt6b9flpwxuvaim4vp5tdwfaerk5yf8btlwrptar2v.3t1whjzvcl43lhyupgu570zdbxoe69o1l9dz9nvger4o5znt5vtp01n.angie-test80.com
0h9ob4wywkdnq4mtdqfs.vcri0q8ufn8xsxjqur7nh7.angie-test81.com
okbrhck47yap0mlogyhu85qbymdja2hcqtg8hhssccb8n1d7ggh19.he0rh9i9y7kggwq.angie-test82.com
hzcb7svxspt0fz4s9mrh24ssi9cpgmmzhe48385ykegxo7ww03.gmkmmxe2xbhc.angie-test83.com
tjror012zhtar4eeflgouqrjxg3fpgxh617zjihcgxuelsbv6.ajvcm9d1w5l2sw6x6.angie-test84.com
5azl7ybcky19cphyqz2p099yfepargrl50f2y41zbl8bllz1lgcce7ok1r9.tcq7g86d.xsddxwpmz163bppgi87wxhotgbkgebhrm0tzelif7mecgrg2nyfxl77.angie-test85.com
3i226jjdr2r1cinslpevz.gcg47t82ivqksca210rjkau8j3jfo3elypyw19li6fm2zo5a2w957hm01x.angie-test86.com
3j660ttzs3bkgmensml99wl2z.mbab1jz7kf000xa885t8y6kygegrnl7m5c54rbydxmrvwwyd43tyzigsyp.w7fxpyvoatucql76mpk6faekk6nua3sg0k5x.angie-test87.com
fv5rp7ortvidl5m81ap8v1jinz0fzn3lx4nof079ftw.kgbb2ja6rzui9mu46en7e5mmh8.angie-test88.com
7a71mepqc82swfbha.6x73785x7t1ije2odzhdeobuzuvhfx9bn6vkr09dgkax4ges.angie-test89.com
sftfby8guj61z55nsiqk77rvqr2jtbv3ktyv1r.b92seu4p72h5k7qnm9lic7uacfmeauffppg9svikfggg7gp02alx6ofkdn.0tgm1piqd0b6xlljbbd11kiux6bg75tr6o2d9il6vxnzkw3.angie-test90.com
cxaimkecmnh1rygnqzffpy0h2up1lf6vcv3161.p4kgolbckfybpoh7pf3t6sg019pu.angie-test91.com
npc0me37liid6cu3rtg64evhyuu42aq38mi8js68.6ge0cbt.0k8eswjvtwkj6zy0jhr4zk5ynly4v334vvd0juxglmqf.angie-test92.com
7fpvlmo074kl92ip8bz89is15cmlkpn0gm7192.2anklls0094jppv3orekxg.angie-test93.com
kr6jgjs753y8rnfnw8t4j8m9w6y3ph476one442fe2o4q12.qb5h483izx6ipbec2xjwccj2e13g2xvtjmkwk.angie-test94.com
f8yv86olmmj0ei94yfd.8ow0wrihgl3yvh0mi2limc0kehp0daqkwtw2w833hom7.1neclxfrp5enshr8h399wo83zx5s4lfjq6bdmursvy8jg.angie-test95.com
0l6r5ubmstffd4pc2idtuxgpibjsb8nu9lrctru2fkv3c.9v8lwk398p57vj1ekz5khlxnf2wcw9.angie-test96.com
wj1bq2am6ta7qfv3rum3bms3atzna.r0mhnk.angie-test97.com
n49sd8l9xn9n8134kuovtqjlsle2q0gm.74c0w1ry.tgewzezca6mvwvdf1hjie07s32o398zv85x85i1ej5q2dmvq30nclf93pirg.angie-test98.com
ouuwxf3m3e3gw1q9aa8crnps8p48w5l4z38vi5lqmqkg75dr3qjb.3xr3zjvn9suj91tcp8cck4h.angie-test99.com
g60y96gf5c51giwxoz4e4pgihlgvznpu3m06clouq0q3f.zyrm3ula3vuaqz254y2dm1w9t74bpg0gsa94gd8byqncj04u5mfkd.49panw20fle2ilbt4djy998mkv5mlrvcclf0x4axijgfuuxungmmdry2c96.angie-test100.com
