package Test::Nginx;

# (C) 2022 Web Server LLC
# (C) Maxim Dounin

# Generic module for Angie tests.

###############################################################################

use warnings;
use strict;

use Exporter qw/ import /;

BEGIN {
	our @EXPORT = qw/ log_in log_out http http_get http_head port /;
	our @EXPORT_OK = qw/
		http_gzip_request http_gzip_like http_start http_end http_content
	/;
	our %EXPORT_TAGS = (
		gzip => [ qw/ http_gzip_request http_gzip_like / ]
	);
}

###############################################################################

use File::Basename qw/ basename /;
use File::Path qw/ rmtree /;
use File::Spec qw//;
use File::Temp qw/ tempdir /;
use IO::Socket;
use POSIX qw/ waitpid WNOHANG /;
use Socket qw/ CRLF /;
use Test::More qw//;

use Test::Nginx::Config;
use Test::API qw/ api_status traverse_api_status /;

###############################################################################

our $NGINX = defined $ENV{TEST_ANGIE_BINARY} ? $ENV{TEST_ANGIE_BINARY}
	: '../objs/angie';
our %ports = ();

sub new {
	my $self = {};
	bless $self;

	$self->{_pid} = $$;
	$self->{_alerts} = 1;
	$self->{_errors_to_skip} = {};

	my $tname = (caller(0))[1];
	my $basename = basename($tname, '.t');

	$self->{_testdir} = tempdir(
		"angie-test-$basename-XXXXXXXXXX",
		TMPDIR => 1
	)
		or die "Can't create temp directory: $!\n";
	$self->{_testdir} =~ s!\\!/!g if $^O eq 'MSWin32';

	Test::More::BAIL_OUT("no $NGINX binary found")
		unless -x $NGINX;

	return $self;
}

sub DESTROY {
	my ($self) = @_;
	local $?;

	return if $self->{_pid} != $$;

	$self->stop();
	$self->stop_daemons();
	$self->stop_resolver();

	if (Test::More->builder->expected_tests) {
		local $Test::Nginx::TODO = 'alerts' unless $self->{_alerts};

		my @alerts = $self->find_in_file('error.log', qr/.+\[alert\].+/);

		local $Test::Nginx::TODO = 'alerts' if @alerts
			&& $^O eq 'solaris'
			&& ! grep { $_ !~ /phantom event/ } @alerts;

		local $Test::Nginx::TODO = 'alerts' if @alerts
			&& $^O eq 'MSWin32'
			&& ! grep { $_ !~ qr/CloseHandle|TerminateProcess/ }
				@alerts;

		Test::More::is(join("\n", @alerts), '', 'no alerts');
	}

	if (Test::More->builder->expected_tests) {
		foreach my $level (qw(crit emerg)) {
			my $errors_re = join('|',
				@{ $self->{_errors_to_skip}{$level} // [] });

			my @errors = $self->find_in_file('error.log', qr/.+\[$level\].+/);

			if (length $errors_re) {

				Test::More::ok(
					! (grep { $_ !~ qr/$errors_re/ } @errors),
					"no unexpected $level errors")
				or Test::More::diag("all $level errors: "
					. join("\n", @errors));

				unless (scalar @errors) {
					Test::More::diag(
						"expected $level errors that are not in the log:");
					Test::More::diag(
						Test::More::explain($self->{_errors_to_skip}{$level}));
				}

			} else {
				my $errors = join("\n", @errors);
				Test::More::ok($errors eq '', "no $level errors")
					or Test::More::diag("all $level errors: $errors");
			}
		}
	}

	if (Test::More->builder->expected_tests) {
		my $errors = join "\n",
			$self->find_in_file('error.log', qr/.+Sanitizer.+/);
		Test::More::is($errors, '', 'no sanitizer errors');
	}

	if (Test::More->builder->expected_tests && $ENV{TEST_ANGIE_VALGRIND}) {
		my $errors = $self->grep_file('valgrind.log', qr/^==\d+== .+/m);
		Test::More::is($errors, '', 'no valgrind errors');
	}

	if ($ENV{TEST_ANGIE_CATLOG}) {
		system("cat $self->{_testdir}/error.log");
	}

	my $leave = defined $ENV{TEST_ANGIE_LEAVE} ? $ENV{TEST_ANGIE_LEAVE} : 0;
	if ($leave eq 'onfail') {
		my $tests_passed = grep { $_ } (Test::More->builder->summary);

		$leave = 0 if Test::More->builder->is_passing
			&& $tests_passed == Test::More->builder->expected_tests;
	}

	if (!$leave) {
		eval { rmtree($self->{_testdir}); };
	}
}

sub has($;) {
	my ($self, @features) = @_;

	foreach my $feature (@features) {
		Test::More::plan(skip_all => "no $feature available")
			unless $self->has_module($feature)
			or $self->has_feature($feature);
	}

	return $self;
}

sub has_module($) {
	my ($self, $feature) = @_;

	my %regex = (
		sni	=> 'TLS SNI support enabled',
		tickets	=> 'TLS SNI support enabled',
		mail	=> '--with-mail((?!\S)|=dynamic)',
		flv	=> '--with-http_flv_module',
		perl	=> '--with-http_perl_module',
		http_api
			=> '(?s)^(?!.*--without-http_api_module)',
		auth_request
			=> '--with-http_auth_request_module',
		realip	=> '--with-http_realip_module',
		sub	=> '--with-http_sub_module',
		acme	=> '--with-http_acme_module',
		debug   => '--with-debug',
		charset	=> '(?s)^(?!.*--without-http_charset_module)',
		gzip	=> '(?s)^(?!.*--without-http_gzip_module)',
		ssi	=> '(?s)^(?!.*--without-http_ssi_module)',
		mirror	=> '(?s)^(?!.*--without-http_mirror_module)',
		userid	=> '(?s)^(?!.*--without-http_userid_module)',
		access	=> '(?s)^(?!.*--without-http_access_module)',
		auth_basic
			=> '(?s)^(?!.*--without-http_auth_basic_module)',
		autoindex
			=> '(?s)^(?!.*--without-http_autoindex_module)',
		geo	=> '(?s)^(?!.*--without-http_geo_module)',
		map	=> '(?s)^(?!.*--without-http_map_module)',
		referer	=> '(?s)^(?!.*--without-http_referer_module)',
		rewrite	=> '(?s)^(?!.*--without-http_rewrite_module)',
		proxy	=> '(?s)^(?!.*--without-http_proxy_module)',
		fastcgi	=> '(?s)^(?!.*--without-http_fastcgi_module)',
		uwsgi	=> '(?s)^(?!.*--without-http_uwsgi_module)',
		scgi	=> '(?s)^(?!.*--without-http_scgi_module)',
		grpc	=> '(?s)^(?!.*--without-http_grpc_module)',
		memcached
			=> '(?s)^(?!.*--without-http_memcached_module)',
		limit_conn
			=> '(?s)^(?!.*--without-http_limit_conn_module)',
		limit_req
			=> '(?s)^(?!.*--without-http_limit_req_module)',
		empty_gif
			=> '(?s)^(?!.*--without-http_empty_gif_module)',
		browser	=> '(?s)^(?!.*--without-http_browser_module)',
		upstream_hash
			=> '(?s)^(?!.*--without-http_upstream_hash_module)',
		upstream_ip_hash
			=> '(?s)^(?!.*--without-http_upstream_ip_hash_module)',
		upstream_least_conn
			=> '(?s)^(?!.*--without-http_upstream_least_conn_mod)',
		upstream_random
			=> '(?s)^(?!.*--without-http_upstream_random_module)',
		upstream_keepalive
			=> '(?s)^(?!.*--without-http_upstream_keepalive_modu)',
		upstream_zone
			=> '(?s)^(?!.*--without-http_upstream_zone_module)',
		upstream_sticky
			=> '(?s)^(?!.*--without-http_upstream_sticky_module)',
		docker
			=> '(?s)^(?!.*--without-http_docker_module)',
		http	=> '(?s)^(?!.*--without-http(?!\S))',
		cache	=> '(?s)^(?!.*--without-http-cache)',
		pop3	=> '(?s)^(?!.*--without-mail_pop3_module)',
		imap	=> '(?s)^(?!.*--without-mail_imap_module)',
		smtp	=> '(?s)^(?!.*--without-mail_smtp_module)',
		pcre	=> '(?s)^(?!.*--without-pcre)',
		ntls	=> '--with-ntls',
		split_clients
			=> '(?s)^(?!.*--without-http_split_clients_module)',
		stream	=> '--with-stream((?!\S)|=dynamic)',
		stream_access
			=> '(?s)^(?!.*--without-stream_access_module)',
		stream_geo
			=> '(?s)^(?!.*--without-stream_geo_module)',
		stream_limit_conn
			=> '(?s)^(?!.*--without-stream_limit_conn_module)',
		stream_map
			=> '(?s)^(?!.*--without-stream_map_module)',
		stream_mqtt_preread
			=> '--with-stream_mqtt_preread_module',
		stream_pass
			=> '(?s)^(?!.*--without-stream_pass_module)',
		stream_rdp_preread
			=> '--with-stream_rdp_preread_module',
		stream_return
			=> '(?s)^(?!.*--without-stream_return_module)',
		stream_set
			=> '(?s)^(?!.*--without-stream_set_module)',
		stream_split_clients
			=> '(?s)^(?!.*--without-stream_split_clients_module)',
		stream_ssl
			=> '--with-stream_ssl_module',
		stream_ssl_preread
			=> '--with-stream_ssl_preread_module',
		stream_upstream_hash
			=> '(?s)^(?!.*--without-stream_upstream_hash_module)',
		stream_upstream_least_conn
			=> '(?s)^(?!.*--without-stream_upstream_least_conn_m)',
		stream_upstream_random
			=> '(?s)^(?!.*--without-stream_upstream_random_modul)',
		stream_upstream_zone
			=> '(?s)^(?!.*--without-stream_upstream_zone_module)',
		stream_upstream_sticky
			=> '(?s)^(?!.*--without-stream_upstream_sticky_module)',
	);

	my $re = $regex{$feature};
	$re = $feature if !defined $re;

	$self->{_configure_args} = `$NGINX -V 2>&1`
		if !defined $self->{_configure_args};

	return 1 if $self->{_configure_args} =~ $re;

	my %modules = (
		http_geoip
			=> 'ngx_http_geoip_module',
		image_filter
			=> 'ngx_http_image_filter_module',
		perl	=> 'ngx_http_perl_module',
		xslt	=> 'ngx_http_xslt_filter_module',
		mail	=> 'ngx_mail_module',
		stream	=> 'ngx_stream_module',
		stream_geoip
			=> 'ngx_stream_geoip_module',
	);

	my $module = $modules{$feature};
	if (defined $module && defined $ENV{TEST_ANGIE_GLOBALS}) {
		$re = qr/load_module\s+[^;]*\Q$module\E[-\w]*\.so\s*;/;
		return 1 if $ENV{TEST_ANGIE_GLOBALS} =~ $re;
	}

	return 0;
}

sub has_feature($) {
	my ($self, $feature) = @_;

	if ($feature eq 'symlink') {
		return $^O ne 'MSWin32';
	}

	if ($feature eq 'unix') {
		return $^O ne 'MSWin32';
	}

	if ($feature eq 'udp') {
		return $^O ne 'MSWin32';
	}

	if ($feature =~ /^socket_ssl/) {
		eval { require IO::Socket::SSL; };
		return 0 if $@;
		eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
		return 0 if $@;
		if ($feature eq 'socket_ssl') {
			return 1;
		}
		if ($feature eq 'socket_ssl_sni') {
			eval { IO::Socket::SSL->can_client_sni() or die; };
			return !$@;
		}
		if ($feature eq 'socket_ssl_alpn') {
			eval { IO::Socket::SSL->can_alpn() or die; };
			return !$@;
		}
		if ($feature eq 'socket_ssl_sslversion') {
			return IO::Socket::SSL->can('get_sslversion');
		}
		if ($feature eq 'socket_ssl_reused') {
			return IO::Socket::SSL->can('get_session_reused');
		}
		return 0;
	}

	if ($feature =~ /^(openssl|libressl):([0-9.]+)([a-z]*)/) {
		my $library = $1;
		my $need = $2;
		my $patch = $3;

		$self->{_configure_args} = `$NGINX -V 2>&1`
			if !defined $self->{_configure_args};

		return 0 unless
			$self->{_configure_args}
			=~ /with $library ([0-9.]+)([a-z]*)/i;

		my @v = (split(/\./, $1), unpack("C*", $2));
		my ($n, $v);

		for $n (split(/\./, $need), unpack("C*", $patch)) {
			$v = shift @v || 0;
			return 0 if $n > $v;
			return 1 if $v > $n;
		}

		return 1;
	}

	if ($feature eq 'cryptx') {
		eval { require Crypt::Misc; };
		return 0 if $@;
		eval { die if $Crypt::Misc::VERSION < 0.067; };
		return !$@;
	}

	return 0;
}

sub has_version($) {
	# compatibility with tests merged from nginx
	return 1;
}

sub has_daemon($) {
	my ($self, $daemon) = @_;

	if ($^O eq 'MSWin32') {
		`for %i in ($daemon.exe) do \@echo | set /p x=%~\$PATH:i`
			or Test::More::plan(skip_all => "$daemon not found");
		return $self;
	}

	if ($^O eq 'solaris') {
		Test::More::plan(skip_all => "$daemon not found")
			unless `command -v $daemon`;
		return $self;
	}

	Test::More::plan(skip_all => "$daemon not found")
		unless `which $daemon 2>/dev/null`;

	return $self;
}

sub try_run($$) {
	my ($self, $message, $check_message) = @_;

	eval {
		open OLDERR, ">&", \*STDERR; close STDERR;
		$self->run();
		open STDERR, ">&", \*OLDERR;
	};

	return $self unless $@;

	if ($ENV{TEST_ANGIE_VERBOSE}) {
		open F, '<', $self->{_testdir} . '/error.log'
			or die "Can't open error.log: $!";
		log_core($_) while (<F>);
		close F;
	}

	my $message_found = 0;
	if ($check_message) {
		$message_found =
			($self->read_file('error.log') =~ quotemeta($message));
	}

	Test::More::plan(skip_all => $message)
		if $message_found || !$check_message;

	return $self;
}

sub retry_run($$) {
	my ($self, $attempts) = @_;

	for my $k (1 .. $attempts) {
		eval {
			open OLDERR, ">&", \*STDERR; close STDERR;
			$self->run();
			open STDERR, ">&", \*OLDERR;
		};

		$k = $k + 1;

		return $self unless $@;
		print("# attempt to run #$k/$attempts failed\n");
	}
	return 0;
}

sub plan($) {
	my ($self, $plan) = @_;

	$plan += 1 if $ENV{TEST_ANGIE_VALGRIND};

	Test::More::plan(tests => $plan + 5);

	return $self;
}

sub todo_alerts() {
	my ($self) = @_;

	$self->{_alerts} = 0;

	return $self;
}

sub skip_errors_check {
	my ($self, $level, @pattern) = @_;

	$self->{_errors_to_skip}{$level} //= [];
	push @{ $self->{_errors_to_skip}{$level} }, @pattern;

	return $self;
}

sub skip_api_check {
	my $self = shift;
	$self->{_api_skipped} = 1;
	return $self;
}

sub run(;$) {
	my ($self, $conf) = @_;

	my $testdir = $self->{_testdir};

	if (defined $conf) {
		my $c = `cat $conf`;
		$self->write_file_expand('nginx.conf', $c);
	}

	if ($ENV{TEST_ANGIE_CATCONF}) {
		Test::More::diag('------------------------------------------');
		Test::More::diag($self->read_file('nginx.conf'));
		Test::More::diag('------------------------------------------');
	}

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		# nginx main process and its workers will have the same process group
		# this will give us the ability to kill them simultaneously
		# using kill '-KILL', $pgrp
		setpgrp;

		my @globals = $self->{_test_globals} ?
			() : ('-g', "pid $testdir/nginx.pid; "
			. "error_log $testdir/error.log debug;");
		my @valgrind = (not $ENV{TEST_ANGIE_VALGRIND}) ?
			() : ('valgrind', '-q',
			"--log-file=$testdir/valgrind.log");
		exec(@valgrind, $NGINX, '-p', "$testdir/", '-c', 'nginx.conf',
			'-e', 'error.log', '--log-level=debug', @globals)
			or die "Unable to exec(): $!\n";
	}

	# wait for nginx to start

	my $nginx_started = $self->waitforfile("$testdir/nginx.pid", $pid);
	unless ($nginx_started) {

		# try to kill pid to prevent tests from hanging
		$self->_stop_pid($pid, 1)
			unless defined $nginx_started;

		die "Can't start nginx";
	}

	for (1 .. 50) {
		last if $^O ne 'MSWin32';
		last if $self->read_file('error.log') =~ /create thread/;
		select undef, undef, undef, 0.1;
	}

	$self->{_started} = 1;
	return $self;
}

sub port {
	my ($num, %opts) = @_;
	my ($sock, $lock, $port);

	goto done if defined $ports{$num};

	my $socket = sub {
		IO::Socket::INET->new(
			Proto => 'tcp',
			LocalAddr => '127.0.0.1:' . shift,
			Listen => 1,
			Reuse => ($^O ne 'MSWin32'),
		);
	};

	my $socketl = sub {
		IO::Socket::INET->new(
			Proto => 'udp',
			LocalAddr => '127.0.0.1:' . shift,
		);
	};

	($socket, $socketl) = ($socketl, $socket) if $opts{udp};

	$port = $num;

	for (1 .. 10) {
		$port = int($port / 500) * 500 + int(rand(500)) unless $_ == 1;

		$lock = $socketl->($port) or next;
		$sock = $socket->($port) and last;
	}

	die "Port limit exceeded" unless defined $lock and defined $sock;

	$ports{$num} = {
		port => $port,
		socket => $lock
	};

done:
	return $ports{$num}{socket} if $opts{socket};
	return $ports{$num}{port};
}

sub dump_config() {
	my ($self) = @_;

	my $testdir = $self->{_testdir};

	my @globals = $self->{_test_globals} ?
		() : ('-g', "pid $testdir/nginx.pid; "
		. "error_log $testdir/error.log debug;");
	my $command = "$NGINX -T -p $testdir/ -c nginx.conf "
		. "-e error.log " . join(' ', @globals);

	return qx/$command 2>&1/;
}

# nginx -t
# returns exit code and message
sub test_config() {
	my ($self) = @_;

	my $testdir = $self->{_testdir};

	my @globals = $self->{_test_globals} ?
		() : ('-g', "pid $testdir/nginx.pid; "
		. "error_log $testdir/error.log;");
	my $command = "$NGINX -t -p $testdir/ -c nginx.conf "
		. "-e test_config_error.log " . join(' ', @globals);

	my $res = system("$command > $testdir/test_config.log 2>&1");
	my $exit_code = $? >> 8;

	my $message = $self->read_file('test_config.log');

	# nginx -t creates an empty pid file
	# we need to delete it before starting nginx
	unlink "$testdir/nginx.pid";

	return ($exit_code, $message);
}

sub waitforfile($;$) {
	my ($self, $file, $pid) = @_;
	my $exited;

	# wait for file to appear
	# or specified process to exit

	for (1 .. 200) {
		return 1 if -e $file;
		return 0 if $exited;
		$exited = waitpid($pid, WNOHANG) != 0 if $pid;
		select undef, undef, undef, 0.1;
	}

	my $tname = (caller(1))[1];
	Test::More::diag("$tname:\t$file was not created after 20 seconds");

	return undef;
}

sub waitforsocket($) {
	my ($self, $peer) = @_;

	# wait for socket to accept connections

	for (1 .. 50) {
		my $s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => $peer,
		);

		return 1 if defined $s;

		select undef, undef, undef, 0.1;
	}

	return undef;
}

sub waitforsslsocket($) {
	my ($self, $peer) = @_;

	# wait for socket to accept connections

	for (1 .. 50) {
		my $s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => $peer,
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE()
		);

		return 1 if defined $s;

		select undef, undef, undef, 0.1;
	}

	return undef;
}

sub start_resolver {
	my $self   = shift;
	my $port   = shift;
	my $addrs  = shift;
	my $params = shift // {};

	$self->has_daemon('dnsmasq');

	my $conf = << "EOF";
# listen on this port
port=$port
# no need for dhcp
no-dhcp-interface=
# do not read /etc/hosts
no-hosts
# do not read /etc/resolv.conf
no-resolv
# take records from this file
addn-hosts=%%TESTDIR%%/test_hosts
EOF

	foreach my $nxaddr (@{ $params->{nxaddrs} // [] }) {
		$conf .= "address=/$nxaddr/\n";
	}

	foreach my $nxserver (@{ $params->{nxservers} // [] }) {
		$conf .= "server=/$nxserver/\n";
	}

	foreach my $srv (@{ $params->{srvs} // [] }) {
		$conf .= "srv-host=$srv\n";
	}

	my $hosts = '';
	while (my ($domain, $ips) = each %{ $addrs }) {
		foreach my $ip (@{ $ips }) {
			$hosts .= "$ip $domain\n";
		}
	}

	# always add this to test for resolver start
	$hosts .= "127.0.0.1 dns.example.com\n";

	$self->write_file_expand('dns.conf', $conf);
	$self->write_file('test_hosts', $hosts);

	my $d = $self->testdir();
	$self->run_daemon('dnsmasq', '-C', "$d/dns.conf", '-k',
		"--log-facility=$d/dns.log", '-q', "--pid-file=$d/dnsmasq.pid");

	my $resolver_pid = $self->{_daemons}[-1];

	$self->wait_for_resolver('127.0.0.1', $port, 'dns.example.com',
		'127.0.0.1');

	# wait for pid file to appear
	$self->waitforfile("$d/dnsmasq.pid", $resolver_pid)
		or die "Can't start dnsmasq on port $port";
}

sub stop_resolver {
	my ($self) = @_;

	my $pid;
	if (-e $self->testdir() . '/dnsmasq.pid') {
		$pid = $self->read_file('dnsmasq.pid');
		chomp $pid;
	}

	unless ($pid) {
		return;
	}

	$self->_stop_pid($pid, 1);

	my $is_running = `ps -h $pid | grep -v defunct | wc -l`;
	$is_running =~ s/^\s+|\s+$//g;

	if ($is_running) {
		Test::More::diag("$0: resolver $pid is not stopped!");
		Test::More::diag(`ps -h $pid`);
	}

	undef $self->{resolver};
}

sub restart_resolver {
	my $self = shift;
	$self->stop_resolver();
	$self->start_resolver(@_);
}

sub wait_for_resolver {
	my ($self, $server, $port, $name, $expected) = @_;

	my $dig = `which dig`;

	if (not $dig) {
		print("# warn: dig not found, falling back to timeout\n");
		select undef, undef, undef, 5;
		return 2;
	}

	my $reply;

	for (1 .. 50) {
		$reply = `dig \@$server -p $port +short +timeout=1 $name`;
		return 1 if index($reply, $expected) != -1;
		select undef, undef, undef, 0.1;
	}
	return undef;
}

sub reload() {
	my ($self, $api_gen_url) = @_;

	return $self unless $self->{_started};

	my $generation;

	if ($api_gen_url) {
		$generation = http_get_value($api_gen_url);
	}

	my $pid = $self->read_file('nginx.pid');

	if ($^O eq 'MSWin32') {
		my $testdir = $self->{_testdir};
		my @globals = $self->{_test_globals} ?
			() : ('-g', "pid $testdir/nginx.pid; "
			. "error_log $testdir/error.log debug;");
		system($NGINX, '-p', $testdir, '-c', "nginx.conf",
			'-s', 'reload', '-e', 'error.log', @globals) == 0
			or die "system() failed: $?\n";

	} else {
		kill 'HUP', $pid;
	}

	if ($api_gen_url) {
		my $new_generation;
		for (1 .. 50) {
			$new_generation = http_get_value($api_gen_url);
			return if $new_generation == $generation + 1;

			select undef, undef, undef, 0.1;
		}
	}

	return $self;
}

sub _stop_pid {
	my ($self, $pid, $force) = @_;

	my $exited;

	unless ($force) {

		# let's try graceful shutdown first
		kill 'QUIT', $pid;

		for (1 .. 900) {
			$exited = waitpid($pid, WNOHANG) != 0;
			last if $exited;
			select undef, undef, undef, 0.1;
		}
	}

	# then try fast shutdown
	if (!$exited) {
		kill 'TERM', $pid;

		for (1 .. 900) {
			$exited = waitpid($pid, WNOHANG) != 0;
			last if $exited;
			select undef, undef, undef, 0.1;
		}
	}

	# last try: brutal kill
	# this will kill the master process and all its worker processes
	if (!$exited) {
		kill '-KILL', getpgrp($pid);

		waitpid($pid, 0);
	}

	return $self;
}

sub stop() {
	my ($self) = @_;

	$self->test_api();

	return $self unless $self->{_started};

	my $pid = $self->read_file('nginx.pid');

	$self->_stop_pid($pid);

	$self->{_started} = 0;

	return $self;
}

sub stop_daemons() {
	my ($self) = @_;

	while ($self->{_daemons} && scalar @{$self->{_daemons}}) {
		my $p = shift @{$self->{_daemons}};
		kill $^O eq 'MSWin32' ? 9 : 'TERM', $p;

		my $exited;

		for (1 .. 50) {
			$exited = waitpid($p, WNOHANG) != 0;
			last if $exited;
			select undef, undef, undef, 0.1;
		}

		if (!$exited) {
			kill $^O eq 'MSWin32' ? 9 : 'TERM', $p;
			waitpid($p, 0);
		}
	}

	return $self;
}

sub read_file($) {
	my ($self, $name) = @_;
	local $/;

	open F, '<', $self->{_testdir} . '/' . $name
		or die "Can't open $name: $!";
	my $content = <F>;
	close F;

	return $content;
}

sub grep_file($$) {
	my ($self, $name, $regex) = @_;

	my $lines = $self->read_file($name);

	$regex = qr/.*\Q$regex\E.*/m if ref($regex) eq '';

	return join "\n", $lines =~ /$regex/g;
}

sub find_in_file {
	my ($self, $name, $pattern) = @_;

	open F, '<', $self->{_testdir} . '/' . $name
		or die "Can't open $name: $!";

	my @found;
	while (my $line = <F>) {
		next unless $line =~ $pattern;
		push @found, $line;
	}

	return @found;
}

sub write_file($$) {
	my ($self, $name, $content) = @_;

	open F, '>' . $self->{_testdir} . '/' . $name
		or die "Can't create $name: $!";
	binmode F;
	print F $content;
	close F;

	return $self;
}

sub write_file_expand($$) {
	my ($self, $name, $content) = @_;

	$content =~ s/%%TEST_GLOBALS%%/$self->test_globals()/gmse;
	$content =~ s/%%TEST_GLOBALS_HTTP%%/$self->test_globals_http()/gmse;
	$content =~ s/%%TEST_GLOBALS_STREAM%%/$self->test_globals_stream()/gmse;
	$content =~ s/%%TESTDIR%%/$self->{_testdir}/gms;

	$content =~ s/127\.0\.0\.1:(8\d\d\d)/'127.0.0.1:' . port($1)/gmse;

	$content =~ s/%%PORT_(\d+)%%/port($1)/gmse;
	$content =~ s/%%PORT_(\d+)_UDP%%/port($1, udp => 1)/gmse;

	$content .= "%%AUTO_GENERATED_API1%%";

	$content
		=~ s/%%AUTO_GENERATED_API(\d*)%%/$self->auto_generated_api($1)/gmse;

	return $self->write_file($name, $content);
}

sub run_daemon($;@) {
	my ($self, $code, @args) = @_;

	my $pid = fork();
	die "Can't fork daemon: $!\n" unless defined $pid;

	if ($pid == 0) {
		if (ref($code) eq 'CODE') {
			$code->(@args);
			exit 0;
		} else {
			exec($code, @args);
			exit 0;
		}
	}

	$self->{_daemons} = [] unless defined $self->{_daemons};
	push @{$self->{_daemons}}, $pid;

	return $self;
}

sub testdir() {
	my ($self) = @_;
	return $self->{_testdir};
}

sub auto_generated_api {
	my ($self, $add_http) = @_;

	return ''
		if $self->{_api_added};

	return ''
		if $self->{_api_skipped};

	return ''
		unless $self->has_module('http_api') && $self->has_feature('unix');

	eval { require IO::Socket::UNIX; };
	return ''
		if $@;

	$self->{_api_added} = 1;
	$self->{_api_location} = '/auto-generated-api/';
	$self->{_api_socket} = $self->{_testdir} . '/api.sock';

	my $auto_generated_api = <<EOF;

    server {
        listen unix:$self->{_api_socket};

        location $self->{_api_location} {
            api /status/;
        }
    }
EOF

	if ($add_http) {
		my $http_globals = $self->test_globals_http();

		return <<EOF;
http {
    $http_globals
$auto_generated_api
}
EOF
	} else {
		return $auto_generated_api;
	}
}

sub test_globals() {
	my ($self) = @_;

	return $self->{_test_globals}
		if defined $self->{_test_globals};

	my $s = '';

	$s .= "pid $self->{_testdir}/nginx.pid;\n";
	$s .= "error_log $self->{_testdir}/error.log debug;\n";

	$s .= $ENV{TEST_ANGIE_GLOBALS}
		if $ENV{TEST_ANGIE_GLOBALS};

	$s .= $self->test_globals_modules();
	$s .= $self->test_globals_perl5lib() if $s !~ /env PERL5LIB/;

	$self->{_test_globals} = $s;
}

sub test_globals_modules() {
	my ($self) = @_;

	my $modules = $ENV{TEST_ANGIE_MODULES};

	if (!defined $modules) {
		my ($volume, $dir) = File::Spec->splitpath($NGINX);
		$modules = File::Spec->catpath($volume, $dir, '');
	}

	$modules = File::Spec->rel2abs($modules);
	$modules =~ s!\\!/!g if $^O eq 'MSWin32';

	my $s = '';

	$s .= "load_module $modules/ngx_http_geoip_module.so;\n"
		if $self->has_module('http_geoip\S+=dynamic');

	$s .= "load_module $modules/ngx_http_image_filter_module.so;\n"
		if $self->has_module('image_filter\S+=dynamic');

	$s .= "load_module $modules/ngx_http_perl_module.so;\n"
		if $self->has_module('perl\S+=dynamic');

	$s .= "load_module $modules/ngx_http_xslt_filter_module.so;\n"
		if $self->has_module('xslt\S+=dynamic');

	$s .= "load_module $modules/ngx_mail_module.so;\n"
		if $self->has_module('mail=dynamic');

	$s .= "load_module $modules/ngx_stream_module.so;\n"
		if $self->has_module('stream=dynamic');

	$s .= "load_module $modules/ngx_stream_geoip_module.so;\n"
		if $self->has_module('stream_geoip\S+=dynamic');

	return $s;
}

sub test_globals_perl5lib() {
	my ($self) = @_;

	return '' unless $self->has_module('perl');

	my ($volume, $dir) = File::Spec->splitpath($NGINX);
	my $objs = File::Spec->catpath($volume, $dir, '');

	$objs = File::Spec->rel2abs($objs);
	$objs =~ s!\\!/!g if $^O eq 'MSWin32';

	return "env PERL5LIB=$objs/src/http/modules/perl:"
		. "$objs/src/http/modules/perl/blib/arch;\n";
}

sub test_globals_http() {
	my ($self) = @_;

	return $self->{_test_globals_http}
		if defined $self->{_test_globals_http};

	my $s = '';

	$s .= "root $self->{_testdir};\n";
	$s .= "    access_log $self->{_testdir}/access.log;\n";
	$s .= "    client_body_temp_path $self->{_testdir}/client_body_temp;\n";

	$s .= "    fastcgi_temp_path $self->{_testdir}/fastcgi_temp;\n"
		if $self->has_module('fastcgi');

	$s .= "    proxy_temp_path $self->{_testdir}/proxy_temp;\n"
		if $self->has_module('proxy');

	$s .= "    uwsgi_temp_path $self->{_testdir}/uwsgi_temp;\n"
		if $self->has_module('uwsgi');

	$s .= "    scgi_temp_path $self->{_testdir}/scgi_temp;\n"
		if $self->has_module('scgi');

	$s .= "    acme_client_path $self->{_testdir}/acme_client;\n"
		if $self->has_module('acme');

	$s .= $ENV{TEST_ANGIE_GLOBALS_HTTP}
		if $ENV{TEST_ANGIE_GLOBALS_HTTP};

	$s .= "%%AUTO_GENERATED_API%%"
		unless $self->{_api_added};

	$self->{_test_globals_http} = $s;
}

sub test_globals_stream() {
	my ($self) = @_;

	return $self->{_test_globals_stream}
		if defined $self->{_test_globals_stream};

	my $s = '';

	$s .= $ENV{TEST_ANGIE_GLOBALS_STREAM}
		if $ENV{TEST_ANGIE_GLOBALS_STREAM};

	$self->{_test_globals_stream} = $s;
}

###############################################################################

sub log_core {
	return unless $ENV{TEST_ANGIE_VERBOSE};
	my ($prefix, $msg) = @_;
	($prefix, $msg) = ('', $prefix) unless defined $msg;
	$prefix .= ' ' if length($prefix) > 0;

	if (length($msg) > 2048) {
		$msg = substr($msg, 0, 2048)
			. "(...logged only 2048 of " . length($msg)
			. " bytes)";
	}

	$msg =~ s/^/# $prefix/gm;
	$msg =~ s/([^\x20-\x7e])/sprintf('\\x%02x', ord($1)) . (($1 eq "\n") ? "\n" : '')/gmxe;
	$msg .= "\n" unless $msg =~ /\n\Z/;
	print $msg;
}

sub log_out {
	log_core('>>', @_);
}

sub log_in {
	log_core('<<', @_);
}

###############################################################################

sub http_get($;%) {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
GET $url HTTP/1.0
Host: localhost

EOF
}

sub http_head($;%) {
	my ($url, %extra) = @_;
	return http(<<EOF, %extra);
HEAD $url HTTP/1.0
Host: localhost

EOF
}

sub http($;%) {
	my ($request, %extra) = @_;

	my $s = http_start($request, %extra);

	return $s if $extra{start} or !defined $s;
	return http_end($s, %extra);
}

sub http_start($;%) {
	my ($request, %extra) = @_;
	my $s;

	my $port = $extra{SSL} ? 8443 : 8080;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		if (%extra && defined $extra{unix_socket_params}) {
			$s = IO::Socket::UNIX->new(%{ $extra{unix_socket_params} })
				or die "Can't connect to nginx: $!\n";
		} else {
			$s = $extra{socket} || IO::Socket::INET->new(
				Proto => 'tcp',
				PeerAddr => '127.0.0.1:' . port($port),
				%extra
			)
				or die "Can't connect to nginx: $!\n";
		}

		if ($extra{SSL}) {
			require IO::Socket::SSL;
			IO::Socket::SSL->start_SSL(
				$s,
				SSL_version => 'SSLv23',
				SSL_verify_mode =>
					IO::Socket::SSL::SSL_VERIFY_NONE(),
				%extra
			)
				or die $IO::Socket::SSL::SSL_ERROR . "\n";

			if (!defined $extra{SSL_startHandshake}) {
				log_in("ssl cipher: " . $s->get_cipher());
				log_in("ssl cert: "
					. $s->peer_certificate('subject'));
			}
		}

		log_out($request);
		$s->print($request);

		select undef, undef, undef, $extra{sleep} if $extra{sleep};
		return '' if $extra{aborted};

		if ($extra{body}) {
			log_out($extra{body});
			$s->print($extra{body});
		}

		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

sub http_end($;%) {
	my ($s) = @_;
	my $reply;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		local $/;
		$reply = $s->getline();

		$s->close();

		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in("died: $@");
		return undef;
	}

	log_in($reply);
	return $reply;
}

###############################################################################

sub http_gzip_request {
	my ($url) = @_;
	my $r = http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
Accept-Encoding: gzip

EOF
}

sub http_content {
	my ($text) = @_;

	return undef if !defined $text;

	if ($text !~ /(.*?)\x0d\x0a?\x0d\x0a?(.*)/ms) {
		return undef;
	}

	my ($headers, $body) = ($1, $2);

	if ($headers !~ /Transfer-Encoding: chunked/i) {
		return $body;
	}

	my $content = '';
	my $len = -1;

	while ($body =~ /\G\x0d?\x0a?([0-9a-f]+)\x0d\x0a?/gcmsi) {
		$len = hex($1);
		$content .= substr($body, pos($body), $len);
		pos($body) += $len;
	}

	if ($len != 0) {
		$content .= '[no-last-chunk]';
	}

	return $content;
}

sub http_gzip_like {
	my ($text, $re, $name) = @_;

	SKIP: {
		eval { require IO::Uncompress::Gunzip; };
		Test::More::skip(
			"IO::Uncompress::Gunzip not installed", 1) if $@;

		my $in = http_content($text);
		my $out;

		IO::Uncompress::Gunzip::gunzip(\$in => \$out);

		Test::More->builder->like($out, $re, $name);
	}
}

sub http_get_value {
	my ($uri) = @_;
	my $response = http_get($uri);
	my ($headers, $body) = split /\n\r/, $response, 2;
	$body =~ s/^\s+|\s+$//g;
	return $body;
}

###############################################################################

sub prepare_ssl($)
{
	my ($self) = @_;

	$self->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

	my $d = $self->testdir();

	foreach my $name ('localhost') {
		system('openssl req -x509 -new '
			. "-config $d/openssl.conf -subj /CN=$name/ "
			. "-out $d/$name.crt -keyout $d/$name.key "
			. ">>$d/openssl.out 2>&1") == 0
			or die "Can't create certificate for $name: $!\n";
	}
}

# runs tests. allows to run a specific test case
# defined by the environment variable TEST_ANGIE_TC
# usage: TEST_ANGIE_TC='<test_case_name>'
sub run_tests {
	my ($self, $test_cases) = @_;

	while (my ($test_case_name, $test_case_sub) = each %{$test_cases}) {
		my $test_case_params = {};
		if (ref $test_case_sub eq 'HASH') {
			$test_case_params = $test_case_sub->{test_params};
			$test_case_sub    = $test_case_sub->{test_sub};
		}

		SKIP: {
			Test::More::skip "subtest '$test_case_name'", 1
				if defined $ENV{TEST_ANGIE_TC}
					&& $ENV{TEST_ANGIE_TC} ne $test_case_name;

			Test::More::subtest $test_case_name => $test_case_sub,
				$self, $test_case_params;
		}
	}

	return $self;
}

sub test_api {
	my $self = shift;

	return
		if !Test::More->builder->expected_tests || $self->{_api_checked};

	SKIP: {
		if ($self->{_api_skipped}) {
			Test::More::skip 'API (can\'t check)', 1;
		}

		unless ($self->{_api_added}) {
			Test::More::skip 'API (api is not configured)', 1;
		}

		unless ($self->{_started}) {
			Test::More::skip 'API (the server is already stopped)', 1;
		}

		my $unix_socket_params = {
			Peer => $self->{_api_socket},
		};

		my ($res, $details) = traverse_api_status($self->{_api_location},
			api_status($self), unix_socket_params => $unix_socket_params);

		unless ($res) {
			Test::More::diag($details);
		}

		TODO: {
			local $Test::Nginx::TODO = 'Extra keys in API response'
				if $details && $details =~ /\s+Extra:/
					&& $details !~ /\s+Missing:/;

			Test::More::ok($res, 'API');
		}
	}

	$self->{_api_checked} = 1;
}

###############################################################################

1;

###############################################################################
