#!/usr/bin/perl

# (C) 2024 Web Server LLC

# ACME protocol support tests

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use POSIX qw/strftime/;
use File::Path qw/ make_path /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'long test') unless $ENV{TEST_ANGIE_UNSAFE};

my $acme_server_domain = 'localhost:8443';
my $acme_server = "https://$acme_server_domain";
my $resolver_ip = '127.0.0.2';

my @domains = qw(test71.com test72.com test73.com);

# how long the original certificate lives before we renew it (sec)
my $orig_validity_time = 10;

# how long we wait for renewal to complete; this should be long enough
# to verify all the domains in the certificate
my $wait_time = 20;

my $client = 'test1';

plan(skip_all => 'win32') if $^O eq 'MSWin32';
# on FreeBSD, this test requires a loopback configured on 127.0.0.2
plan(skip_all => 'FreeBSD') if $^O eq 'freebsd';
plan(skip_all => 'must be root') if $> != 0;
plan(skip_all => 'one or more testing domains are unavailable')
    if !check_domains();
plan(skip_all => 'ACME server is unavailable')
    unless acme_server_online();

my $ssl_port = port(443);
my $dns_port = port(8982);

my $conf = "
%%TEST_GLOBALS%%

daemon off;

#user root;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver $resolver_ip:%%PORT_8982_UDP%%;

    map \$acme_cert_$client \$cert_$client {
        ''       original.crt;
        default  \$acme_cert_$client;
    }

    map \$acme_cert_$client \$cert_key_$client {
        ''       original.key;
        default  \$acme_cert_key_$client;
    }

    acme_client $client $acme_server/directory
        renew_before_expiry=0
    ;

    server {

        listen               %%PORT_443%% ssl;
        server_name          @domains;

        ssl_certificate      \$cert_$client;
        ssl_certificate_key  \$cert_key_$client;

        acme                 $client;

        location / {
            return           200 \"\$cert_$client\\n\";
        }

    }

    server {
        listen               80;
        server_name          localhost;

        location / {
            return           200 \"HELLO\\n\";
        }
    }
}
";

#print $conf;

my $t = Test::Nginx->new()->has(qw/ acme /)
    ->plan(2)
    ->write_file_expand('nginx.conf', $conf);

my $d = $t->testdir();

$t->run_daemon(\&dns_daemon, $dns_port, $t);
$t->waitforfile($d . '/' . $dns_port);

my $cert_db = "cert_db";
my $cert_db_path = "$d/$cert_db";
my $cert_db_filename = "certs.db";
my $client_dir = "$d/acme_client/$client";
my $cert = "$client_dir/certificate.pem";
my $cert_key = "$client_dir/private.key";

mkdir($cert_db_path);
$t->write_file("$cert_db/$cert_db_filename", '');

make_path($client_dir);

my $alt_names = '';

for my $i (0..$#domains) {
    $alt_names .= sprintf("DNS.%d = %s\n", $i + 1, $domains[$i]);
}

$t->write_file('openssl.conf', <<EOF);
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = \@alt_names
[alt_names]
$alt_names
[ca]
default_ca = my_default_ca
[my_default_ca]
new_certs_dir = $cert_db_path
database      = $cert_db_path/$cert_db_filename
default_md    = default
rand_serial   = 1
policy        = my_ca_policy
copy_extensions = copy
email_in_dn   = no
default_days  = 365
[my_ca_policy]
EOF

# Create a very short-lived certificate, just to see how it gets renewed.
# In this test, we plant this certificate in the client's directory,
# so the client will pick it up at startup and use its expiry time to schedule
# renewal.

my $orig_cert = "$cert";
my $orig_cert_key = "$cert_key";

my $now = time();

my $enddate = strftime("%y%m%d%H%M%SZ", gmtime($now + $orig_validity_time));

system("openssl genrsa -out $d/ca.key 4096 2>/dev/null") == 0
&& system("openssl req -new -x509 -nodes -days 3650 " .
          "-subj '/C=XX/O=Original Test CA' -key $d/ca.key -out $d/ca.crt") == 0
&& system("openssl req -new -nodes -out $d/csr.pem -newkey rsa:4096 " .
          "-keyout $orig_cert_key -subj /C=XX/CN=Original 2>/dev/null") == 0
&& system("openssl ca -batch -notext -config $d/openssl.conf " .
          "-extensions v3_req -startdate 240101080000Z -enddate $enddate " .
          "-out $orig_cert -cert $d/ca.crt -keyfile $d/ca.key " .
          "-in $d/csr.pem 2>/dev/null") == 0
|| die("Can't create the original certificate: $!");

$enddate = `openssl x509 -in $orig_cert -enddate -noout`;

$t->run();

# download a page using the old certificate
my $old_page = get_page();

my $enddate_changed = 0;
my $page_changed = 0;

for (1.. $orig_validity_time + $wait_time) {
    # Periodically read the expiry date of the certificate and see
    # if it's changed. If it has, that means the certificate
    # has been renewed.
    my $s = `openssl x509 -in $cert -enddate -noout`;
    $enddate_changed = $s ne "" && $s ne $enddate;
    last if $enddate_changed;
    sleep 1;
}

if ($enddate_changed) {
    # We already know that the expiry date of the certificate has changed,
    # now we want to download a page and see if the server is using the new
    # certificate.
    my $page = get_page();

    $page_changed = $old_page ne $page;
}

###############################################################################

ok($enddate_changed, "new certificate arrived");
ok($page_changed, "new certificate used");

###############################################################################

sub check_domains {
    my @bad;

    for (@domains) {
        if (scalar grep(/127.0.0.1/, `ping -c 1 -W 1 $_ 2>/dev/null`) == 0) {
            push @bad, $_;
        }
    }

    if (scalar @bad) {
        print("To run this test, your testing domains must resolve to 127.0.0.1.\n");
        print("In most cases this can be achieved by adding the following entries\n");
        print("to your /etc/hosts file:\n");

        for (@bad) {
            print("127.0.0.1 $_\n");
        }
    }

    return !scalar @bad;
}

###############################################################################

sub acme_server_online {

    return defined IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => $acme_server_domain,
    );
}

###############################################################################

sub get_page {
    my $host = $domains[0];

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => "$host:$ssl_port",
    )
    or die "Can't connect to $host: $!\n";

    my $r = http(<<EOF, socket => $s, SSL => 1);
GET / HTTP/1.0
Host: $host

EOF

    return http_content($r);
}

###############################################################################

sub reply_handler {
    my ($recv_data) = @_;

    my (@name, @rdata);

    use constant NOERROR    => 0;
    use constant A          => 1;
    use constant IN         => 1;

    # default values

    my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

    # decode name

    my ($len, $offset) = (undef, 12);
    while (1) {
        $len = unpack("\@$offset C", $recv_data);
        last if $len == 0;
        $offset++;
        push @name, unpack("\@$offset A$len", $recv_data);
        $offset += $len;
    }

    $offset -= 1;
    my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

    my $name = join('.', @name);
    if ($name eq 'localhost' && $type == A) {
        push @rdata, rd_addr($ttl, '127.0.0.1');
    }

    $len = @name;
    pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
        0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
    my ($ttl, $addr) = @_;

    my $code = 'split(/\./, $addr)';

    return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

    pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
    my ($port, $t) = @_;

    my ($data, $recv_data);
    my $socket = IO::Socket::INET->new(
        LocalAddr => $resolver_ip,
        LocalPort => $port,
        Proto => 'udp',
    )
        or die "Can't create listening socket: $!\n";

    # signal we are ready

    open my $fh, '>', $t->testdir() . '/' . $port;
    close $fh;

    while (1) {
        $socket->recv($recv_data, 65536);
        $data = reply_handler($recv_data);
        $socket->send($data);
    }
}

###############################################################################
