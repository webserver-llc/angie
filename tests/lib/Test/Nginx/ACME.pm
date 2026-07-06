package Test::Nginx::ACME;

# (C) 2025 Web Server LLC

# Utils for nginx ACME tests.

# TODO we need check that pebble and challtestsrv are ready to accept requests

###############################################################################

use warnings;
use strict;

use POSIX qw/ waitpid WNOHANG /;
use Test::More;

use Test::Control qw/stop_pid/;
use Test::Nginx qw/port/;

use Fcntl qw(SEEK_SET);

# This module requires pebble and pebble-challtestsrv (see
# https://github.com/letsencrypt/pebble). If you build them from source,
# assume they live in the directory below. Otherwise we expect them to be
# installed system-wide.
use constant ACME_SERVER_DIR => defined $ENV{PEBBLE_PATH}
	? $ENV{PEBBLE_PATH}
	: $ENV{HOME} . '/go/bin';

use constant PEBBLE_KEY => <<"EOF";
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmxTFtw113RK70H9pQmdKs9AxhFmnQ6BdDtp3jOZlWlUO0Blt
MXOUML5905etgtCbcC6RdKRtgSAiDfgx3VWiFMJH++4gUtnaB9SN8GhNSPBpFfSa
2JhWPo9HQNUsAZqlGTV4SzcGRqtWvdZxUiOfQ2TcvyXIqsaD19ivvqI1NhT6bl3t
redTZlzLLM6Wvkw6hfyHrJAPQP8LOlCIeDM4YIce6Gstv6qo9iCD4wJiY4u95HVL
7RK8t8JpZAb7VR+dPhbHEvVpjwuYd5Q05OZ280gFyrhbrKLbqst104GOQT4kQMJG
WxGONyTX6np0Dx6O5jU7dvYvjVVawbJwGuaL6wIDAQABAoIBAGW9W/S6lO+DIcoo
PHL+9sg+tq2gb5ZzN3nOI45BfI6lrMEjXTqLG9ZasovFP2TJ3J/dPTnrwZdr8Et/
357YViwORVFnKLeSCnMGpFPq6YEHj7mCrq+YSURjlRhYgbVPsi52oMOfhrOIJrEG
ZXPAwPRi0Ftqu1omQEqz8qA7JHOkjB2p0i2Xc/uOSJccCmUDMlksRYz8zFe8wHuD
XvUL2k23n2pBZ6wiez6Xjr0wUQ4ESI02x7PmYgA3aqF2Q6ECDwHhjVeQmAuypMF6
IaTjIJkWdZCW96pPaK1t+5nTNZ+Mg7tpJ/PRE4BkJvqcfHEOOl6wAE8gSk5uVApY
ZRKGmGkCgYEAzF9iRXYo7A/UphL11bR0gqxB6qnQl54iLhqS/E6CVNcmwJ2d9pF8
5HTfSo1/lOXT3hGV8gizN2S5RmWBrc9HBZ+dNrVo7FYeeBiHu+opbX1X/C1HC0m1
wJNsyoXeqD1OFc1WbDpHz5iv4IOXzYdOdKiYEcTv5JkqE7jomqBLQk8CgYEAwkG/
rnwr4ThUo/DG5oH+l0LVnHkrJY+BUSI33g3eQ3eM0MSbfJXGT7snh5puJW0oXP7Z
Gw88nK3Vnz2nTPesiwtO2OkUVgrIgWryIvKHaqrYnapZHuM+io30jbZOVaVTMR9c
X/7/d5/evwXuP7p2DIdZKQKKFgROm1XnhNqVgaUCgYBD/ogHbCR5RVsOVciMbRlG
UGEt3YmUp/vfMuAsKUKbT2mJM+dWHVlb+LZBa4pC06QFgfxNJi/aAhzSGvtmBEww
xsXbaceauZwxgJfIIUPfNZCMSdQVIVTi2Smcx6UofBz6i/Jw14MEwlvhamaa7qVf
kqflYYwelga1wRNCPopLaQKBgQCWsZqZKQqBNMm0Q9yIhN+TR+2d7QFjqeePoRPl
1qxNejhq25ojE607vNv1ff9kWUGuoqSZMUC76r6FQba/JoNbefI4otd7x/GzM9uS
8MHMJazU4okwROkHYwgLxxkNp6rZuJJYheB4VDTfyyH/ng5lubmY7rdgTQcNyZ5I
majRYQKBgAMKJ3RlII0qvAfNFZr4Y2bNIq+60Z+Qu2W5xokIHCFNly3W1XDDKGFe
CCPHSvQljinke3P9gPt2HVdXxcnku9VkTti+JygxuLkVg7E0/SWwrWfGsaMJs+84
fK+mTZay2d3v24r9WKEKwLykngYPyZw5+BdWU0E+xx5lGUd3U4gG
-----END RSA PRIVATE KEY-----
EOF

use constant PEBBLE_CERT => <<"EOF";
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIbEfayDFsBtwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMDcx
MjA2MTk0MjEwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCbFMW3DXXdErvQf2lCZ0qz0DGEWadDoF0O2neM5mVa
VQ7QGW0xc5Qwvn3Tl62C0JtwLpF0pG2BICIN+DHdVaIUwkf77iBS2doH1I3waE1I
8GkV9JrYmFY+j0dA1SwBmqUZNXhLNwZGq1a91nFSI59DZNy/JciqxoPX2K++ojU2
FPpuXe2t51NmXMsszpa+TDqF/IeskA9A/ws6UIh4Mzhghx7oay2/qqj2IIPjAmJj
i73kdUvtEry3wmlkBvtVH50+FscS9WmPC5h3lDTk5nbzSAXKuFusotuqy3XTgY5B
PiRAwkZbEY43JNfqenQPHo7mNTt29i+NVVrBsnAa5ovrAgMBAAGjYzBhMA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAiBgNVHREEGzAZgglsb2NhbGhvc3SCBnBlYmJsZYcEfwAAATANBgkq
hkiG9w0BAQsFAAOCAQEAYIkXff8H28KS0KyLHtbbSOGU4sujHHVwiVXSATACsNAE
D0Qa8hdtTQ6AUqA6/n8/u1tk0O4rPE/cTpsM3IJFX9S3rZMRsguBP7BSr1Lq/XAB
7JP/CNHt+Z9aKCKcg11wIX9/B9F7pyKM3TdKgOpqXGV6TMuLjg5PlYWI/07lVGFW
/mSJDRs8bSCFmbRtEqc4lpwlrpz+kTTnX6G7JDLfLWYw/xXVqwFfdengcDTHCc8K
wtgGq/Gu6vcoBxIO3jaca+OIkMfxxXmGrcNdseuUCa3RMZ8Qy03DqGu6Y6XQyK4B
W8zIG6H9SVKkAznM2yfYhW8v2ktcaZ95/OBHY97ZIw==
-----END CERTIFICATE-----
EOF

sub new {
	my ($class, $params) = @_;
	my $self = bless $params, $class;

	die 'No Test::Nginx instance passed to newly created ACME helper object'
		if !defined $self->{t} || ref $self->{t} ne 'Test::Nginx';

	# TODO: Remove this function and its dependents once pebble and
	# challtestsrv have been updated in our testing infrastructure.
	_check_server_version($self);

	$self->{dns_port} //= port(8053);

	return $self;
}

# _check_server_version()
#
# Detects the version of the pebble binary by inspecting its embedded
# Go build info, then sets compatibility flags accordingly.
#
# For more detail on Go build info, see:
#   https://pkg.go.dev/cmd/go#hdr-Print_Go_version
#   https://go.dev/src/debug/buildinfo/buildinfo.go
sub _check_server_version {
	my ($self) = @_;

	# Initially assume we are using recent server versions.
	my $outdated = 0;
	$self->{_cts_dnsserv_opt} = '-dnsserver';
	$self->{_profiles_supported} = 1;
	$self->{_dns_over_tcp} = 1;

	my $pebble = 'pebble';
	my $exe = ACME_SERVER_DIR . "/$pebble";

	my ($data, $err);

	if (!-f $exe) {
		chomp($exe = `which $pebble 2>/dev/null`);

		if ($exe eq '') {
			$err = "$pebble not found on this machine";
			goto done;
		}
	}

	($data, $err) = _extract_elf_section($exe, ".go.buildinfo");

	if (!$data || substr($data, 0, 14) ne "\xff Go buildinf:") {
		$err = "Section '.go.buildinfo' is missing or invalid in '$exe'"
			unless $err;
		goto done;
	}

	my ($path) = $data =~ /path\t([^\n]*)\n/;
	my ($time) = $data =~ /build\tvcs\.time=([^\n]*)\n/;

	if (!$path or !$time) {
		$err = "Build information missing or incomplete in '$exe'";
		goto done;
	}

	if ($path ne 'github.com/letsencrypt/pebble/v2/cmd/pebble') {
		$err = "Unknown package path '$path' in '$exe'";
		goto done;
	}

	($time, $err) = _rfc3339_to_epoch($time);

	if (!$time) {
		goto done;
	}

	# Support for profiles was added in pebble in this commit:
	# https://github.com/letsencrypt/pebble/commit/e08dd94e723a0e8d005d7c6149a8666e4bf5d877
	# Date: Thu Aug 22 08:57:20 2024 -0700 (1724342240 since Epoch).

	if ($time < 1724342240) {
		$self->{_profiles_supported} = 0;
		$outdated = 1;
	}

	# The -dns01 argument was renamed to -dnsserver in challtestsrv in this
	# commit:
	# https://github.com/letsencrypt/pebble/commit/79baa7827c438372f5a1327ea2d6a4d1321bca8e
	# Date: Tue Feb 10 12:38:33 2026 -0500 (1770745113 since Epoch).

	if ($time < 1770745113) {
		$self->{_cts_dnsserv_opt} = '-dns01';
		$outdated = 1;
	}

	# Pebble was changed to always query DNS records for DNS-01/
	# DNS-ACCOUNT-01 validation over TCP instead of UDP in this commit:
	# https://github.com/letsencrypt/pebble/commit/b29f2f5a6388f748815948163c7768a296236827
	# Date: Tue Feb 17 15:33:26 2026 -0800 (1771371206 since Epoch).

	if ($time < 1771371206) {
		$self->{_dns_over_tcp} = 0;
		$outdated = 1;
	}

	note("Outdated ACME server detected, compatibility settings applied")
		if $outdated;

done:

	note("Failed to obtain ACME server version: $err") if $err;
}

# _rfc3339_to_epoch($ts)
#
# Parses an RFC 3339 timestamp string into a Unix epoch integer.
#
# Returns ($epoch, undef) on success, or (undef, $err) on failure.
sub _rfc3339_to_epoch {
	my ($ts) = @_;

	$ts =~ /^
		(\d{4})-(\d{2})-(\d{2})     # YYYY-MM-DD
		T                           # 'T'
		(\d{2}):(\d{2}):(\d{2})     # hh:mm:ss
		(?:\.\d+)?                  # optional fraction of a second
		(Z|([+-])(\d{2}):(\d{2}))   # 'Z' or hh:mm zone offset
	$/x or return (undef, "Couldn't parse time string: $ts");

	my ($y, $m, $d, $H, $M, $S, $tz, $sign, $tzh, $tzm)
		= ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

	# Days since Unix epoch (1970-01-01), using civil date algorithm.
	my $days = _days_from_civil($y, $m, $d);

	my $epoch = $days * 86400 + $H * 3600 + $M * 60 + $S;

	# Apply timezone.
	if ($tz ne 'Z') {
		my $offset = $tzh * 3600 + $tzm * 60;
		# RFC3339: +02:00 means local time is ahead of UTC, therefore subtract.
		$epoch -= ($sign eq '+') ? $offset : -$offset;
	}

	return ($epoch, undef);
}

# _days_from_civil($y, $m, $d)
#
# Howard Hinnant's days-from-civil algorithm (no libraries needed).
# Converts a proleptic Gregorian calendar date to a count of days
# since the Unix epoch (1970-01-01). Works correctly for all dates
# including those before 1970.
sub _days_from_civil {
	my ($y, $m, $d) = @_;

	$y -= $m <= 2;
	my $era = int(($y >= 0 ? $y : $y - 399) / 400);
	my $yoe = $y - $era * 400;                                        # [0, 399]
	my $doy = int((153 * ($m + ($m > 2 ? -3 : 9)) + 2) / 5) + $d - 1; # [0, 365]
	my $doe = $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy;    # [0, 146096]

	return $era * 146097 + $doe - 719468;
}

# ELF header field offsets and sizes, indexed by class (1=ELF32, 2=ELF64).
#
# All offsets are relative to the start of the file.
# Field layout per the ELF spec (man 5 elf):
#
#   ELF32 Ehdr                        ELF64 Ehdr
#   Offset  Size  Field               Offset  Size  Field
#   0       16    e_ident             0       16    e_ident
#   16      2     e_type              16      2     e_type
#   18      2     e_machine           18      2     e_machine
#   20      4     e_version           20      4     e_version
#   24      4     e_entry             24      8     e_entry
#   28      4     e_phoff             32      8     e_phoff
#   32      4     e_shoff  <--        40      8     e_shoff  <--
#   36      4     e_flags             48      4     e_flags
#   40      2     e_ehsize            52      2     e_ehsize
#   42      2     e_phentsize         54      2     e_phentsize
#   44      2     e_phnum             56      2     e_phnum
#   46      2     e_shentsize  <--    58      2     e_shentsize  <--
#   48      2     e_shnum      <--    60      2     e_shnum      <--
#   50      2     e_shstrndx   <--    62      2     e_shstrndx   <--
#   52      -     (end)               64      -     (end)
#
#   ELF32 Shdr                        ELF64 Shdr
#   Offset  Size  Field               Offset  Size  Field
#   0       4     sh_name    <--      0       4     sh_name    <--
#   4       4     sh_type             4       4     sh_type
#   8       4     sh_flags            8       8     sh_flags
#   12      4     sh_addr             16      8     sh_addr
#   16      4     sh_offset  <--      24      8     sh_offset  <--
#   20      4     sh_size    <--      32      8     sh_size    <--
#   24      4     sh_link             40      4     sh_link
#   28      4     sh_info             44      4     sh_info
#   32      4     sh_addralign        48      8     sh_addralign
#   36      4     sh_entsize          56      8     sh_entsize
#   40      -     (end)               64      -     (end)

my %ELF_LAYOUT = (
	1 => {                           # ELF32
		ehdr_size	=> 52,
		e_shoff		=> [32, 'V' ],   # u32
		e_shentsize => [46, 'v' ],   # u16
		e_shnum		=> [48, 'v' ],   # u16
		e_shstrndx	=> [50, 'v' ],   # u16
		sh_name		=> [ 0, 'V' ],   # u32
		sh_offset	=> [16, 'V' ],   # u32
		sh_size		=> [20, 'V' ],   # u32
	},
	2 => {                           # ELF64
		ehdr_size	=> 64,
		e_shoff		=> [40, 'Q' ],   # u64
		e_shentsize => [58, 'v' ],   # u16
		e_shnum		=> [60, 'v' ],   # u16
		e_shstrndx	=> [62, 'v' ],   # u16
		sh_name		=> [ 0, 'V' ],   # u32
		sh_offset	=> [24, 'Q' ],   # u64
		sh_size		=> [32, 'Q' ],   # u64
	},
);

my %UNPACK_SIZE = ( 'v' => 2, 'V' => 4, 'Q' => 8 );

# _extract_elf_section($file, $section_name)
#
# Opens an ELF binary and returns the raw bytes of the named section.
#
# Returns a two-element list ($data, $error):
#   - On success:       ($section_bytes, undef)
#   - Section missing:  (undef, undef)
#   - On error:         (undef, "error message")
#
# Supports ELF32 and ELF64, little-endian and big-endian.
sub _extract_elf_section {
	my ($file, $target_name) = @_;
	my ($err, $ehdr_rest);

	open my $fh, '<:raw', $file
		or return (undef, "Cannot open '$file': $!");

	# Parse e_ident (first 16 bytes).

	my $ident;
	($ident, $err) = _sysread($fh, 16);
	return (undef, "Failed to read ELF ident: $err") if defined $err;

	return (undef, "'$file' is not an ELF file")
		unless substr($ident, 0, 4) eq "\x7fELF";

	my $class  = ord(substr($ident, 4, 1));  # EI_CLASS:  1=32-bit, 2=64-bit
	my $endian = ord(substr($ident, 5, 1));  # EI_DATA:   1=LE,     2=BE

	return (undef, "Unsupported ELF class $class (expected 1 or 2)")
		unless exists $ELF_LAYOUT{$class};
	return (undef, "Unsupported ELF encoding $endian (expected 1 or 2)")
		unless $endian == 1 || $endian == 2;

	my $layout = $ELF_LAYOUT{$class};

	# Endian fixup: the layout table uses 'v'/'V'/'Q' (little-endian).
	# For big-endian files, remap to 'n'/'N'/'Q>'.
	my %le2be = ( 'v' => 'n', 'V' => 'N', 'Q' => 'Q>' );
	if ($endian == 2) {
		$layout = {
			map { $_ => (ref $layout->{$_} eq 'ARRAY'
							? [$layout->{$_}[0], $le2be{$layout->{$_}[1]}]
							: $layout->{$_})
				} keys %$layout
		};
	}

	# Parse the ELF header.

	# We already consumed 16 bytes; read the remainder of the ELF header.
	my $ehdr_rest_size = $layout->{ehdr_size} - 16;
	($ehdr_rest, $err) = _sysread($fh, $ehdr_rest_size);
	return (undef, "Failed to read ELF header: $err") if defined $err;

	# _field() extracts a value from a buffer using an [offset, fmt] descriptor.
	# $buf_origin is the absolute file offset where $buf begins, used to convert
	# the descriptor's absolute field offset into a buffer-relative position.
	my $field = sub {
		my ($buf, $buf_origin, $desc) = @_;
		my ($off, $fmt) = @$desc;
		my $rel = $off - $buf_origin;
		return unpack($fmt, substr($buf, $rel, $UNPACK_SIZE{$fmt =~ s/>$//r}));
	};

	my $shoff     = $field->($ehdr_rest, 16, $layout->{e_shoff});
	my $shentsize = $field->($ehdr_rest, 16, $layout->{e_shentsize});
	my $shnum     = $field->($ehdr_rest, 16, $layout->{e_shnum});
	my $shstrndx  = $field->($ehdr_rest, 16, $layout->{e_shstrndx});

	return (undef, "'$file': no section headers (shnum=0)")
		unless $shnum > 0;
	return (undef, "'$file': shstrndx $shstrndx out of range (shnum=$shnum)")
		unless $shstrndx < $shnum;

	# Read all section headers.

	sysseek($fh, $shoff, SEEK_SET)
		or return (undef, "'$file': sysseek to section headers failed: $!");

	my @sections;
	for (0 .. $shnum - 1) {
		my $sh;
		($sh, $err) = _sysread($fh, $shentsize);
		return (undef, "Failed to read section header: $err") if defined $err;

		push @sections, {
			name_off => $field->($sh, 0, $layout->{sh_name}),
			offset   => $field->($sh, 0, $layout->{sh_offset}),
			size     => $field->($sh, 0, $layout->{sh_size}),
		};
	}

	# Load the section name string table (.shstrtab).

	my $strtab_sec = $sections[$shstrndx];
	sysseek($fh, $strtab_sec->{offset}, SEEK_SET)
		or return (undef, "'$file': sysseek to .shstrtab failed: $!");

	my $strtab;
	($strtab, $err) = _sysread($fh, $strtab_sec->{size});
	return (undef, "Failed to read .shstrtab: $err") if defined $err;

	# Match section names and extract the target.

	for my $sec (@sections) {
		my $off = $sec->{name_off};
		next if $off >= length($strtab);

		# Extract null-terminated name directly — no regex, handles \n in names.
		my $nul	 = index($strtab, "\x00", $off);
		my $name = $nul >= 0
			? substr($strtab, $off, $nul - $off)
			: substr($strtab, $off);

		next unless $name eq $target_name;

		return ('', undef) if $sec->{size} == 0;  # valid but empty (e.g. .bss)

		sysseek($fh, $sec->{offset}, SEEK_SET)
			or return (undef, "'$file': sysseek to section '$name' failed: $!");

		my $data;
		($data, $err) = _sysread($fh, $sec->{size});
		return (undef, "Failed to read section '$name': $err") if defined $err;

		return ($data, undef);
	}

	return (undef, undef);  # section not found
}

# _sysread($fh, $n)
#
# Reads exactly $n bytes via sysread. Short reads are not expected and
# are treated as errors.
#
# Returns ($data, undef) on success, or (undef, $error_message) on failure.
sub _sysread {
	my ($fh, $n) = @_;
	return ('', undef) if $n == 0;

	my $buf = '';
	my $rc = sysread($fh, $buf, $n);

	return (undef, $!) unless defined $rc;
	return (undef, "EOF") unless $rc == $n;
	return ($buf,  undef);
}

sub start_pebble {
	my ($self, $params) = @_;

	my $pebble = ACME_SERVER_DIR . '/pebble';
	if (!-f $pebble) {
		$pebble = 'pebble';
		$self->{t}->has_daemon($pebble);
	}

	# Create a leaf certificate and a private key for the Pebble HTTPS server.
	# Copied from
	# https://github.com/letsencrypt/pebble/tree/main/test/certs/localhost

	my $pebble_key = 'pebble-key.pem';
	$self->{t}->write_file($pebble_key, PEBBLE_KEY);

	my $pebble_cert = 'pebble-cert.pem';
	$self->{t}->write_file($pebble_cert, PEBBLE_CERT);

	my $mgmt_addr = defined $params->{mgmt_port}
		? '0.0.0.0:' . $params->{mgmt_port}
		: '';

	my $tls_port    = $params->{tls_port}    // port(5001);
	my $http_port   = $params->{http_port}   // port(5002);
	my $pebble_port = $params->{pebble_port} // port(14000);
	my $dns_port = defined $params->{dns_port}
		? $params->{dns_port}
		: $self->{dns_port};

	my $d = $self->{t}->testdir();

	# a default validity period of 7776000 is defined in ca/ca.go
	my $certificate_validity_period
		= $params->{certificate_validity_period} // 7776000;

	my $pebble_config = 'pebble-config.json';
	my $sep;

	my $eab = "    \"externalAccountBindingRequired\": false";

	if ($params->{eab}) {
		$eab = "    \"externalAccountBindingRequired\": true,\n";
		$eab .= "    \"externalAccountMACKeys\": {\n";
		$sep = "      ";

		for my $key (keys %{ $params->{eab} }) {
			$eab .= "$sep\"$key\": \"$params->{eab}{$key}\"";
			$sep = ",\n      ";
		}

		$eab .= "\n    }";
	}

	die("Profiles specified but not supported by current pebble version")
		if $params->{profiles} and !$self->{_profiles_supported};

	if (!$params->{profiles} and $params->{certificate_validity_period}) {
		# If no profiles are specified, pebble will internally add a profile
		# named "default" with a default validity period.  For compatibility
		# with the existing ACME tests which don't use profiles but use the
		# certificate_validity_period parameter, add a "default" profile
		# with the specified validity period.
		$params->{profiles} = {
			default => {
				description => 'The default profile',
				validity_period => $params->{certificate_validity_period}
			}
		};
	}

	my $profiles = '';

	if ($params->{profiles}) {
		$profiles .= ",\n    \"profiles\": {\n";
		$sep = '';

		for my $profile (keys %{ $params->{profiles} }) {
			my $p = $params->{profiles}->{$profile};

			my $d = $p->{description}
				  ? $p->{description}
				  : $profile;

			my $v = $p->{validity_period}
				  ? $p->{validity_period}
				  : $certificate_validity_period;

			$profiles .=
				"$sep" .
				"      \"$profile\": {\n" .
				"        \"description\": \"$d\",\n" .
				"        \"validityPeriod\": $v\n" .
				"      }";

			$sep = ",\n";
		}

		$profiles .="\n    }";
	}

	# The certificateValidityPeriod setting is ignored in newer versions
	# of pebble.  It has been replaced by validityPeriod, which must now
	# be specified separately for each profile.

	$self->{t}->write_file($pebble_config, <<"EOF");
{
  "pebble": {
    "listenAddress": "0.0.0.0:$pebble_port",
    "managementListenAddress": "$mgmt_addr",
    "certificate": "$d/$pebble_cert",
    "privateKey": "$d/$pebble_key",
    "httpPort": $http_port,
    "tlsPort": $tls_port,
    "ocspResponderURL": "",
    "domainBlocklist": ["blocked-domain.example"],
    "retryAfter": {
        "authz": 3,
        "order": 5
    },
    "certificateValidityPeriod": $certificate_validity_period,
${eab}${profiles}
  }
}
EOF

	# Percentage of valid nonces that will be rejected by the server.
	# The default value is 5, and we don't want any of the nonces
	# to be rejected unless explicitly specified.
	$ENV{PEBBLE_WFE_NONCEREJECT} //= 0;

	my $pid = $self->{t}->run_daemon($pebble,
		'-config', "$d/$pebble_config",
		'-dnsserver', '127.0.0.1:' . $dns_port
	);

	$self->{t}{pebble} = $pid;

	# pebbles's interfaces listen on 0.0.0.0, but we check their availability
	# on 127.0.0.1 -- the way they will actually be used.

	if ($mgmt_addr) {
		my $mgmt_port = $params->{mgmt_port};

		eval { $self->{t}->waitforsslsocket("127.0.0.1:$mgmt_port"); };
		if ($@) {
			$self->stop_pebble();
			die "Couldn't start pebble's management interface on $mgmt_addr, "
				. "pid $pid: $@";
		}

		note("Pebble's management interface running on $mgmt_addr, pid $pid");
	}

	eval { $self->{t}->waitforsslsocket("127.0.0.1:$pebble_port"); };
	if ($@) {
		$self->stop_pebble();
		die "Couldn't start pebble on 0.0.0.0:$pebble_port, pid $pid: $@";
	}

	note("Pebble running on 0.0.0.0:$pebble_port, pid $pid");
}

sub stop_pebble {
	my ($self) = @_;

	my $pid = $self->{t}{pebble};

	return unless $pid;

	my $exited;

	# Ctrl-C is the proper way to stop pebble
	kill 'INT', $pid;
	for (1 .. 900) {
		$exited = waitpid($pid, WNOHANG) != 0;
		last if $exited;
		select undef, undef, undef, 0.1;
	}

	stop_pid($pid, 1) unless $exited;
	undef $self->{t}{pebble};

	note("Pebble $pid stopped");
}

sub start_challtestsrv {
	my ($self, $params) = @_;

	my $challtestsrv = ACME_SERVER_DIR . '/pebble-challtestsrv';
	if (!-f $challtestsrv) {
		$challtestsrv = 'pebble-challtestsrv';
		$self->{t}->has_daemon($challtestsrv);
	}

	# TODO make me a constant? or global variable?
	my $mgmt_port = $params->{mgmt_port} // port(8055);
	my $http_port = defined $params->{http_port}
		? ':' . $params->{http_port}
		: '';
	my $dns_port = defined $params->{dns_port}
		? $params->{dns_port}
		: $self->{dns_port};
	my $tlsalpn_port = defined $params->{tlsalpn_port}
		? ':' . $params->{tlsalpn_port}
		: '';

	my $d = $self->{t}->testdir();
	my $pid = $self->{t}->run_daemon($challtestsrv,
		'-management', ":$mgmt_port",
		'-defaultIPv6', '',
		"$self->{_cts_dnsserv_opt}", ":$dns_port",
		'-http01', $http_port,
		'-https01', '',
		'-doh', '',
		'-tlsalpn01', $tlsalpn_port,
	);

	$self->{t}{challtestsrv} = $pid;

	# challtestsrv's management interface listens on 0.0.0.0:$mgmt_port
	# but we check its availability on 127.0.0.1:$mgmt_port -- the way
	# it will actually be used.

	eval { $self->{t}->waitforsocket("127.0.0.1:$mgmt_port"); };
	if ($@) {
		$self->stop_challtestsrv();
		die "Couldn't start challtestsrv's management interface on "
			. "0.0.0.0:$mgmt_port, pid $pid: $@";
	}

	note("Challtestsrv's management interface running on 0.0.0.0:$mgmt_port, "
		. "pid $pid");

	eval { $self->{t}->waitforsocket("127.0.0.1:$dns_port"); };
	if ($@) {
		$self->stop_challtestsrv();
		die "Couldn't start challtestsrv's DNS server on "
			. "127.0.0.1:$dns_port, pid $pid: $@";
	}

	note("Challtestsrv's DNS server running on 127.0.0.1:$dns_port, pid $pid");
}

sub stop_challtestsrv {
	my ($self) = @_;

	my $pid = $self->{t}{challtestsrv};

	return unless $pid;

	my $exited;

	# Ctrl-C is the proper way to stop challtestsrv
	kill 'INT', $pid;
	for (1 .. 900) {
		$exited = waitpid($pid, WNOHANG) != 0;
		last if $exited;
		select undef, undef, undef, 0.1;
	}

	stop_pid($pid, 1) unless $exited;
	undef $self->{t}{challtestsrv};

	note("Challtestsrv $pid stopped");
}

1;
