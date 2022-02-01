package Test::Nginx::HTTP3;

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Module for nginx QUIC tests.

###############################################################################

use warnings;
use strict;

use IO::Socket::INET;
use IO::Select;
use Data::Dumper;

use Test::Nginx;

sub new {
	my $self = {};
	bless $self, shift @_;

	my ($port, %extra) = @_;

	require Crypt::KeyDerivation;
	require Crypt::PK::X25519;
	require Crypt::PRNG;
	require Crypt::AuthEnc::GCM;
	require Crypt::Mode::CTR;
	require Crypt::Digest;
	require Crypt::Mac::HMAC;

	$self->{socket} = IO::Socket::INET->new(
		Proto => "udp",
		PeerAddr => '127.0.0.1:' . port($port || 8980),
	);

	$self->{repeat} = 0;
	$self->{token} = '';
	$self->{psk_list} = $extra{psk_list} || [];

	$self->{sni} = exists $extra{sni} ? $extra{sni} : 'localhost';
	$self->{opts} = $extra{opts};

	$self->{zero} = pack("x5");

	$self->{buf} = '';

	$self->init();
	$self->init_key_schedule();
	$self->initial();
	$self->handshake() or return;

	return $self;
}

sub init {
	my ($self, $early_data) = @_;
	$self->{keys} = [];
	$self->{pn} = [[-1, -1, -1, -1], [-1, -1, -1, -1]];
	$self->{crypto_in} = [[],[],[],[]];
	$self->{stream_in} = [];
	$self->{frames_in} = [];
	$self->{tlsm} = ();
	$self->{tlsm}{$_} = ''
		for 'ch', 'sh', 'ee', 'cert', 'cv', 'sf', 'cf', 'nst';
	$self->{requests} = 0;

	# Initial

	$self->{odcid} = undef;
	$self->{scid} = Crypt::PRNG::random_bytes(17);
	$self->{dcid} = Crypt::PRNG::random_bytes(18);
	$self->{salt} = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17"
			.  "\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
	$self->{ncid} = [];
	$self->{early_data} = $early_data;

	$self->retry();
}

sub retry {
	my ($self) = @_;
	my $prk = Crypt::KeyDerivation::hkdf_extract($self->{dcid},
		$self->{salt}, 'SHA256');

	Test::Nginx::log_core('||', "scid = " . unpack("H*", $self->{scid}));
	Test::Nginx::log_core('||', "dcid = " . unpack("H*", $self->{dcid}));
	Test::Nginx::log_core('||', "prk = " . unpack("H*", $prk));

	$self->set_traffic_keys('tls13 client in', 0, 'w', $prk);
	$self->set_traffic_keys('tls13 server in', 0, 'r', $prk);
}

sub init_key_schedule {
	my ($self) = @_;
	$self->{psk} = $self->{psk_list}[0];
	$self->{es_prk} = Crypt::KeyDerivation::hkdf_extract(
		$self->{psk}->{secret} || pack("x32"), pack("x32"), 'SHA256');
	$self->{sk} = Crypt::PK::X25519->new->generate_key;
}

sub initial {
	my ($self, $ed) = @_;
	$self->{tlsm}{ch} = $self->build_tls_client_hello();
	my $ch = $self->{tlsm}{ch};
	my $crypto = build_crypto($ch);
	my $padding = 1200 - length($crypto);
	$padding = 0 if $padding < 0 || $self->{psk}->{ed};
	my $payload = $crypto . pack("x$padding");
	my $initial = $self->encrypt_aead($payload, 0);

	if ($ed && $self->{psk}->{ed}) {
		$self->set_traffic_keys('tls13 c e traffic', 1, 'w',
			$self->{es_prk}, Crypt::Digest::digest_data('SHA256',
			$self->{tlsm}{ch}));

#		my $ed = "\x0a\x02\x08\x00\x04\x02\x06\x1f\x0d\x00\x0a"
#			. $self->build_stream("\x01\x06\x00\x00\xc0");
		$payload = $ed;
#		$payload = $self->build_stream("GET /\n");
		$padding = 1200 - length($crypto) - length($payload);
		$payload .= pack("x$padding") if $padding > 0;
		$initial .= $self->encrypt_aead($payload, 1);
	}

	$self->{socket}->syswrite($initial);
}

sub handshake {
	my ($self) = @_;
	my $buf = '';

	$self->read_tls_message(\$buf, \&parse_tls_server_hello) or return;

	my $sh = $self->{tlsm}{sh};
	my $extens_len = unpack("C*", substr($sh, 6 + 32 + 4, 2)) * 8
		+ unpack("C*", substr($sh, 6 + 32 + 5, 1));
	my $extens = substr($sh, 6 + 32 + 4 + 2, $extens_len);
	my $pub = key_share($extens);
	Test::Nginx::log_core('||', "pub = " . unpack("H*", $pub));

	my $pk = Crypt::PK::X25519->new;
	$pk->import_key_raw($pub, "public");
	my $shared_secret = $self->{sk}->shared_secret($pk);
	Test::Nginx::log_core('||', "shared = " . unpack("H*", $shared_secret));

	# tls13_advance_key_schedule

	$self->{hs_prk} = hkdf_advance($shared_secret, $self->{es_prk});
	Test::Nginx::log_core('||', "hs = " . unpack("H*", $self->{hs_prk}));

	# derive_secret_with_transcript

	my $digest = Crypt::Digest::digest_data('SHA256', $self->{tlsm}{ch}
		. $self->{tlsm}{sh});
	$self->set_traffic_keys('tls13 c hs traffic', 2, 'w',
		$self->{hs_prk}, $digest);
	$self->set_traffic_keys('tls13 s hs traffic', 2, 'r',
		$self->{hs_prk}, $digest);

	$self->read_tls_message(\$buf, \&parse_tls_encrypted_extensions);

	unless (keys %{$self->{psk}}) {
		$self->read_tls_message(\$buf, \&parse_tls_certificate);
		$self->read_tls_message(\$buf, \&parse_tls_certificate_verify);
	}

	$self->read_tls_message(\$buf, \&parse_tls_finished);

	# tls13_advance_key_schedule(application)

	$self->{ms_prk} = hkdf_advance(pack("x32"), $self->{hs_prk});
	Test::Nginx::log_core('||',
		"master = " . unpack("H*", $self->{ms_prk}));

	# derive_secret_with_transcript(application)

	$digest = Crypt::Digest::digest_data('SHA256', $self->{tlsm}{ch}
		. $self->{tlsm}{sh} . $self->{tlsm}{ee} . $self->{tlsm}{cert}
		. $self->{tlsm}{cv} . $self->{tlsm}{sf});
	$self->set_traffic_keys('tls13 c ap traffic', 3, 'w',
		$self->{ms_prk}, $digest);
	$self->set_traffic_keys('tls13 s ap traffic', 3, 'r',
		$self->{ms_prk}, $digest);

	# client finished

	my $finished = tls13_finished($self->{keys}[2]{w}{prk}, $digest);
	Test::Nginx::log_core('||', "finished = " . unpack("H*", $finished));

	$self->{tlsm}{cf} = $finished;

	$digest = Crypt::Digest::digest_data('SHA256', $self->{tlsm}{ch}
		. $self->{tlsm}{sh} . $self->{tlsm}{ee} . $self->{tlsm}{cert}
		. $self->{tlsm}{cv} . $self->{tlsm}{sf} . $self->{tlsm}{cf});
	$self->{rms_prk} = hkdf_expand_label("tls13 res master", 32,
		$self->{ms_prk}, $digest);
	Test::Nginx::log_core('||',
		"resumption = " . unpack("H*", $self->{rms_prk}));

	my $crypto = build_crypto($finished);
	$self->{socket}->syswrite($self->encrypt_aead($crypto, 2));
}

#if (!$psk->{ed}) {
#	my $r = "\x0a\x02\x08\x00\x04\x02\x06\x1f\x0d\x00\x0a";
#	$s->syswrite(encrypt_aead($r, 3));
#	$r = "\x01\x06\x00\x00\xc0";
#	$s->syswrite(encrypt_aead($self->build_stream($r), 3));
#}

sub DESTROY {
	my ($self) = @_;

	return unless $self->{socket};
	return unless $self->{keys}[3];
	my $frame = build_cc(0, "graceful shutdown");
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub ping {
	my ($self) = @_;
	my $frame = "\x01\x00\x00\x00";
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub reset_stream {
	my ($self, $sid, $code) = @_;
	my $final_size = $self->{streams}{$sid}{sent};
	my $frame = "\x04" . build_int($sid) . build_int($code)
		. build_int($final_size);
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub stop_sending {
	my ($self, $sid, $code) = @_;
	my $frame = "\x05" . build_int($sid) . build_int($code);
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub new_connection_id {
	my ($self, $seqno, $ret, $id, $token) = @_;
	my $frame = "\x18" . build_int($seqno) . build_int($ret)
		. pack("C", length($id)) . $id . $token;
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub path_challenge {
	my ($self, $data) = @_;
	my $frame = "\x1a" . $data;
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

sub path_response {
	my ($self, $data) = @_;
	my $frame = "\x1b" . $data;
	$self->{socket}->syswrite($self->encrypt_aead($frame, 3));
}

###############################################################################

sub parse_frames {
	my ($buf) = @_;
	my @frames;
	my $offset = 0;

	while ($offset < length($buf)) {
		my ($tlen, $type) = parse_int(substr($buf, $offset));
		$offset += $tlen;
		next if $type == 0;
		my $frame = { type => $type };

		if ($type == 1) {
			$frame->{type} = 'PING';
		}
		if ($type == 2) {
			$frame->{type} = 'ACK';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{largest} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{delay} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{count} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{first} = $val;
			$offset += $len;
		}
		if ($type == 4) {
			$frame->{type} = 'RESET_STREAM';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{sid} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{code} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{final_size} = $val;
			$offset += $len;
		}
		if ($type == 5) {
			$frame->{type} = 'STOP_SENDING';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{sid} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{code} = $val;
			$offset += $len;
		}
		if ($type == 6) {
			my ($olen, $off) = parse_int(substr($buf, $offset));
			$offset += $olen;
			my ($llen, $len) = parse_int(substr($buf, $offset));
			$offset += $llen;
			$frame->{type} = 'CRYPTO';
			$frame->{length} = $len;
			$frame->{offset} = $off;
			$frame->{payload} = substr($buf, $offset, $len);
			$offset += $len;
		}
		if ($type == 7) {
			$frame->{type} = 'NEW_TOKEN';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$offset += $len;
			$frame->{token} = substr($buf, $offset, $val);
			$offset += $val;
		}
		if (($type & 0xf8) == 0x08) {
			$frame->{type} = 'STREAM';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{id} = $val;
			$offset += $len;
			if ($type & 0x4) {
				($len, $val) = parse_int(substr($buf, $offset));
				$frame->{offset} = $val;
				$offset += $len;
			} else {
				$frame->{offset} = 0;
			}
			if ($type & 0x2) {
				($len, $val) = parse_int(substr($buf, $offset));
				$frame->{length} = $val;
				$offset += $len;
			} else {
				$frame->{length} = length($buf) - $offset;
			}
			if ($type & 0x1) {
				$frame->{fin} = 1;
			}
			$frame->{payload} =
				substr($buf, $offset, $frame->{length});
			$offset += $frame->{length};
		}
		if ($type == 18 || $type == 19) {
			$frame->{type} = 'MAX_STREAMS';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{val} = $val;
			$frame->{uni} = 1 if $type == 19;
			$offset += $len;
		}
		if ($type == 24) {
			$frame->{type} = 'NCID';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{seqno} = $val;
			$offset += $len;
			($len, $val) = parse_int(substr($buf, $offset));
			$frame->{rpt} = $val;
			$offset += $len;
			$len = unpack("C", substr($buf, $offset, 1));
			$frame->{length} = $len;
			$offset += 1;
			$frame->{cid} = substr($buf, $offset, $len);
			$offset += $len;
			$frame->{token} = substr($buf, $offset, 16);
			$offset += 16;
		}
		if ($type == 26) {
			$frame->{type} = 'PATH_CHALLENGE';
			$frame->{data} = substr($buf, $offset, 8);
			$offset += 8;
		}
		if ($type == 27) {
			$frame->{type} = 'PATH_RESPONSE';
			$frame->{data} = substr($buf, $offset, 8);
			$offset += 8;
		}
		if ($type == 28 || $type == 29) {
			$frame->{type} = 'CONNECTION_CLOSE';
			my ($len, $val) = parse_int(substr($buf, $offset));
			$frame->{error} = $val;
			$offset += $len;
			if ($type == 28) {
				($len, $val) = parse_int(substr($buf, $offset));
				$frame->{frame_type} = $val;
				$offset += $len;
			}
			($len, $val) = parse_int(substr($buf, $offset));
			$offset += $len;
			$frame->{phrase} = substr($buf, $offset, $val);
			$offset += $val;
		}
		if ($type == 30) {
			$frame->{type} = 'HANDSHAKE_DONE';
		}
		push @frames, $frame;
	}
	return \@frames;
}

sub handle_frames {
	my ($self, $frames, $level) = @_;

	my @frames = grep { $_->{type} eq 'CRYPTO' } @$frames;
	while (my $frame = shift @frames) {
		insert_crypto($self->{crypto_in}[$level], [
			$frame->{offset},
			$frame->{length},
			$frame->{payload},
		]);

		$self->parse_tls_nst() if $level == 3;
	}

	@frames = grep { $_->{type} eq 'STREAM' } @$frames;
	while (my $frame = shift @frames) {
		$self->{stream_in}[$frame->{id}] ||= { buf => [], pos => 0 };
		insert_crypto($self->{stream_in}[$frame->{id}]->{buf}, [
			$frame->{offset},
			$frame->{length},
			$frame->{payload},
			$frame->{fin},
		]);
	}

	@frames = grep { $_->{type} eq 'NCID' } @$frames;
	while (my $frame = shift @frames) {
		push @{$self->{ncid}}, $frame;
	}

	my $ack = $self->{ack}[$level];

	# stop tracking acknowledged ACK ranges

	@frames = grep { $_->{type} eq 'ACK' } @$frames;
	while (my $frame = shift @frames) {
		my $max = $frame->{largest};
		my $min = $max - $frame->{first};

		for my $num ($min .. $max) {
			for my $pn (keys %$ack) {
				delete $ack->{$pn} if $ack->{$pn} == $num;
			}
		}
	}

	$self->{socket}->syswrite($self->encrypt_aead(build_ack($ack), $level));

	for my $pn (keys %$ack) {
		$ack->{$pn} = $self->{pn}[0][$level] if $ack->{$pn} == -1;
	}

	my ($frame) = grep { $_->{type} eq 'NEW_TOKEN' } @$frames;
	$self->{token} = $frame->{token} || '';

	push @{$self->{frames_in}}, grep { $_->{type} ne 'CRYPTO'
		&& $_->{type} ne 'STREAM' } @$frames;
}

sub insert_crypto {
	my ($crypto, $frame) = @_;
	my $i;

	for ($i = 0; $i < scalar @$crypto; $i++) {
		# frame][crypto][frame
		my $this = @$crypto[$i];
		if (@$frame[0] <= @$this[0] &&
			@$frame[0] + @$frame[1] >= @$this[0] + @$this[1])
		{
			my $old = substr(@$frame[2], @$this[0] - @$frame[0],
				@$this[1]);
			die "bad inner" if $old ne @$this[2];
			splice @$crypto, $i, 1; $i--;
		}
	}

	return push @$crypto, $frame if !@$crypto;

	for ($i = 0; $i < @$crypto; $i++) {
		if (@$frame[0] <= @{@$crypto[$i]}[0] + @{@$crypto[$i]}[1]) {
			last;
		}
	}

	return push @$crypto, $frame if $i == @$crypto;

	my $this = @$crypto[$i];
	my $next = @$crypto[$i + 1];

	if (@$frame[0] + @$frame[1] == @$this[0]) {
		# frame][crypto
		@$this[0] = @$frame[0];
		@$this[1] += @$frame[1];
		@$this[2] = @$frame[2] . @$this[2];

	} elsif (@$this[0] + @$this[1] == @$frame[0]) {
		# crypto][frame
		@$this[1] += @$frame[1];
		@$this[2] .= @$frame[2];
		@$this[3] = @$frame[3];

	} elsif (@$frame[0] + @$frame[1] < @$this[0]) {
		# frame..crypto
		return splice @$crypto, $i, 0, $frame;

	} else {
		# overlay
		my ($b1, $b2) = @$this[0] < @$frame[0]
			? ($this, $frame) : ($frame, $this);
		my ($o1, $o2) = @$this[0] + @$this[1] < @$frame[0] + @$frame[1]
			? ($this, $frame) : ($frame, $this);
		my $offset = @$b2[0] - @$b1[0];
		my $length = @$o1[0] + @$o1[1] - @$b2[0];
		my $old = substr @$b1[2], $offset, $length, @$b2[2];
		die "bad repl" if substr(@$b1[2], $offset, $length) ne $old;
		@$this = (@$b1[0], @$o2[0] + @$o2[1] - @$b1[0], @$b1[2]);
	}

	return if !defined $next;

	# combine with next overlay if any
	if (@$this[0] + @$this[1] >= @$next[0]) {
		my $offset = @$next[0] - @$this[0];
		my $length = @$this[0] + @$this[1] - @$next[0];
		my $old = substr @$this[2], $offset, $length, @$next[2];
		die "bad repl2" if substr(@$this[2], $offset, $length) ne $old;
		@$this[1] = @$next[0] + @$next[1] - @$this[0];
		splice @$crypto, $i + 1, 1;
	}
}

###############################################################################

sub save_session_tickets {
	my ($self, $content) = @_;

	my $nst_len = unpack("n", substr($content, 2, 2));
	my $nst = substr($content, 4, $nst_len);

	my $psk = {};
	my $lifetime = substr($nst, 0, 4);
	$psk->{age_add} = substr($nst, 4, 4);
	my $nonce_len = unpack("C", substr($nst, 8, 1));
	my $nonce = substr($nst, 9, $nonce_len);
	my $len = unpack("n", substr($nst, 8 + 1 + $nonce_len, 2));
	$psk->{ticket} = substr($nst, 11 + $nonce_len, $len);

	my $extens_len = unpack("n", substr($nst, 11 + $nonce_len + $len, 2));
	my $extens = substr($nst, 11 + $nonce_len + $len + 2, $extens_len);

	$psk->{ed} = early_data($extens);
	$psk->{secret} = hkdf_expand_label("tls13 resumption", 32,
		$self->{rms_prk}, $nonce);
	push @{$self->{psk_list}}, $psk;
}

sub decode_pn {
	my ($self, $pn, $pnl, $level) = @_;
	my $expected = $self->{pn}[1][$level] + 1;
	my $pn_win = 1 << $pnl * 8;
	my $pn_hwin = $pn_win / 2;

	$pn |= $expected & ~($pn_win - 1);

	if ($pn <= $expected - $pn_hwin && $pn < (1 << 62) - $pn_win) {
		$pn += $pn_win;

	} elsif ($pn > $expected + $pn_hwin && $pn >= $pn_win) {
		$pn -= $pn_win;
	}

	return $pn;
}

sub decrypt_aead {
	my ($self, $buf) = @_;
	my $flags = unpack("C", substr($buf, 0, 1));
	return 0, $self->decrypt_retry($buf) if ($flags & 0xf0) == 0xf0;
	my $level = $flags & 0x80 ? $flags - 0xc0 >> 4 : 3;
	my $offpn = 1 + length($self->{scid}) if $level == 3;
	$offpn = (
		$offpn = unpack("C", substr($buf, 5, 1)),
		$self->{scid} = substr($buf, 6, $offpn),
		$offpn = unpack("C", substr($buf, 6 + length($self->{scid}), 1)),
		$self->{dcid} =
			substr($buf, 6 + length($self->{scid}) + 1, $offpn),
		7 + ($level == 0) + length($self->{scid})
			+ length($self->{dcid})) if $level != 3;
	my ($len, $val) = $level != 3
		? parse_int(substr($buf, $offpn))
		: (0, length($buf) - $offpn);
	$offpn += $len;

	my $sample = substr($buf, $offpn + 4, 16);
	my ($ad, $pnl, $pn) = $self->decrypt_ad($buf,
		$self->{keys}[$level]{r}{hp}, $sample, $offpn, $level == 3);
	Test::Nginx::log_core('||', "ad = " . unpack("H*", $ad));
	$pn = $self->decode_pn($pn, $pnl, $level);
	my $nonce = substr(pack("x12") . pack("N", $pn), -12)
		^ $self->{keys}[$level]{r}{iv};
	my $ciphertext = substr($buf, $offpn + $pnl, $val - 16 - $pnl);
	my $tag = substr($buf, $offpn + $val - 16, 16);
	my $plaintext = Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES',
		$self->{keys}[$level]{r}{key}, $nonce, $ad, $ciphertext, $tag);
	return if !defined $plaintext;
	Test::Nginx::log_core('||',
		"pn = $pn, level = $level, length = " . length($plaintext));

	$self->{pn}[1][$level] = $pn;
	$self->{ack}[$level]{$pn} = -1;
	$self->{ack}[$_] = undef for (0 .. $level - 1);

	return ($level, $plaintext,
		substr($buf, length($ad . $ciphertext . $tag)), '');
}

sub decrypt_ad {
	my ($self, $buf, $hp, $sample, $offset, $short) = @_;
	my $m = Crypt::Mode::CTR->new('AES');
	my $mask = $m->encrypt($self->{zero}, $hp, $sample);
	substr($buf, 0, 1) ^= substr($mask, 0, 1) & ($short ? "\x1f" : "\x0f");
	my $pnl = unpack("C", substr($buf, 0, 1) & "\x03") + 1;
	for (my $i = 0; $i < $pnl; $i++) {
		substr($buf, $offset + $i, 1) ^= substr($mask, $i + 1, 1);
	}
	my $pn = unpack("C", substr($buf, $offset, $pnl));
	my $ad = substr($buf, 0, $offset + $pnl);
	return ($ad, $pnl, $pn);
}

sub encrypt_aead {
	my ($self, $payload, $level) = @_;
	my $pn = ++$self->{pn}[0][$level];
	my $ad = pack("C", $level == 3 ? 0x40 : 0xc + $level << 4) | "\x03";
	$ad .= "\x00\x00\x00\x01" unless $level == 3;
	$ad .= $level == 3 ? $self->{dcid} :
		pack("C", length($self->{dcid})) . $self->{dcid}
		. pack("C", length($self->{scid})) . $self->{scid};
	$ad .= build_int(length($self->{token})) . $self->{token}
		if $level == 0;
	$ad .= build_int(length($payload) + 16 + 4) unless $level == 3;
	$ad .= pack("N", $pn);
	my $nonce = substr(pack("x12") . pack("N", $pn), -12)
		^ $self->{keys}[$level]{w}{iv};
	my ($ciphertext, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate(
		'AES', $self->{keys}[$level]{w}{key}, $nonce, $ad, $payload);
	my $sample = substr($ciphertext . $tag, 0, 16);

	$ad = $self->encrypt_ad($ad, $self->{keys}[$level]{w}{hp},
		$sample, $level == 3);
	return $ad . $ciphertext . $tag;
}

sub encrypt_ad {
	my ($self, $ad, $hp, $sample, $short) = @_;
	my $m = Crypt::Mode::CTR->new('AES');
	my $mask = $m->encrypt($self->{zero}, $hp, $sample);
	substr($ad, 0, 1) ^= substr($mask, 0, 1) & ($short ? "\x1f" : "\x0f");
	substr($ad, -4) ^= substr($mask, 1);
	return $ad;
}

sub decrypt_retry {
	my ($self, $buf) = @_;
	my $off = unpack("C", substr($buf, 5, 1));
	$self->{scid} = substr($buf, 6, $off);
	$self->{odcid} = $self->{dcid};
	$self->{dcid} = unpack("C", substr($buf, 6 + $off, 1));
	$self->{dcid} = substr($buf, 6 + $off + 1, $self->{dcid});
	my $token = substr($buf, 6 + $off + 1 + length($self->{dcid}), -16);
	my $tag = substr($buf, -16);
	my $pseudo = pack("C", length($self->{odcid})) . $self->{odcid}
		. substr($buf, 0, -16);
	return ($tag, retry_verify_tag($pseudo), $token);
}

sub retry_verify_tag {
	my $key = "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a"
		. "\x1d\x76\x6b\x54\xe3\x68\xc8\x4e";
	my $nonce = "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb";
	my (undef, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES',
		$key, $nonce, shift, '');
	return $tag;
}

sub set_traffic_keys {
	my ($self, $label, $level, $direction, $secret, $digest) = @_;
	my $prk = hkdf_expand_label($label, 32, $secret, $digest);
	my $key = hkdf_expand_label("tls13 quic key", 16, $prk);
	my $iv = hkdf_expand_label("tls13 quic iv", 12, $prk);
	my $hp = hkdf_expand_label("tls13 quic hp", 16, $prk);
	$self->{keys}[$level]{$direction}{prk} = $prk;
	$self->{keys}[$level]{$direction}{key} = $key;
	$self->{keys}[$level]{$direction}{iv} = $iv;
	$self->{keys}[$level]{$direction}{hp} = $hp;
}

sub hmac_finished {
	my ($key, $digest) = @_;
	my $finished_key = hkdf_expand_label("tls13 finished", 32, $key);
	Crypt::Mac::HMAC::hmac('SHA256', $finished_key, $digest);
}

sub tls13_finished {
	my ($key, $digest) = @_;
	my $hmac = hmac_finished($key, $digest);
	"\x14\x00" . pack('n', length($hmac)) . $hmac;
}

sub binders {
	my ($key, $digest) = @_;
	my $hmac = hmac_finished($key, $digest);
	pack('n', length($hmac) + 1) . pack('C', length($hmac)) . $hmac;
}

sub hkdf_advance {
	my ($secret, $prk) = @_;
	my $digest0 = Crypt::Digest::digest_data('SHA256', '');
	my $expand = hkdf_expand_label("tls13 derived", 32, $prk, $digest0);
	Crypt::KeyDerivation::hkdf_extract($secret, $expand, 'SHA256');
}

sub hkdf_expand_label {
	my ($label, $len, $prk, $context) = @_;
	$context = '' if !defined $context;
	my $info = pack("C3", 0, $len, length($label)) . $label
		. pack("C", length($context)) . $context;
	return Crypt::KeyDerivation::hkdf_expand($prk, 'SHA256', $len, $info);
}

sub key_share {
	my ($extens) = @_;
	my $offset = 0;
	while ($offset < length($extens)) {
		my $ext = substr($extens, $offset, 2);
		my $len = unpack("C", substr($extens, $offset + 2, 1)) * 8 +
			unpack("C", substr($extens, $offset + 3, 1));
		if ($ext eq "\x00\x33") {
			return substr($extens, $offset + 4 + 4, $len - 4);
		}
		$offset += 4 + $len;
	}
}

sub early_data {
	my ($extens) = @_;
	my $offset = 0;
	while ($offset < length($extens)) {
		my $ext = substr($extens, $offset, 2);
		my $len = unpack("C", substr($extens, $offset + 2, 1)) * 8 +
			unpack("C", substr($extens, $offset + 3, 1));
		if ($ext eq "\x00\x2a") {
			return substr($extens, $offset + 4, $len);
		}
		$offset += 4 + $len;
	}
}

###############################################################################

sub build_cc {
	my ($code, $reason) = @_;
	"\x1d" . build_int($code) . build_int(length($reason)) . $reason;
}

sub build_ack {
	my ($ack) = @_;
	my @keys = sort { $b <=> $a } keys %$ack;

	return "\x02" . build_int($keys[0]) . "\x00\x00\x00" if @keys == 1;

	my $min = my $max = shift @keys;
	my @acks = ();
	for my $next (@keys) {
		if ($next == $min - 1) {
			$min = $next;
			next if $next != $keys[-1];
		}
		push @acks, $max, $min;
		$min = $max = $next;
	}

	($max, $min) = splice @acks, 0, 2;
	my $ranges = @acks / 2;

	$ack = "\x02" . build_int($max) . "\x00" . build_int($ranges)
		. build_int($max - $min);

	for (my $smallest = $min; $ranges--; ) {
		my ($max, $min) = splice @acks, 0, 2;
		$ack .= build_int($smallest - $max - 2);
		$ack .= build_int($max - $min);
		$smallest = $min;
	}

	return $ack;
}

sub build_crypto {
	my ($tlsm) = @_;
	"\x06\x00" . build_int(length($tlsm)) . $tlsm;
}

sub build_stream {
	my ($self, $r, %extra) = @_;
	my $stream = $extra{start} ? 0xe : 0xf;
	my $length = $extra{length} ? $extra{length} : build_int(length($r));
	my $offset = build_int($extra{offset} ? $extra{offset} : 0);
	my $sid = defined $extra{sid} ? $extra{sid} : $self->{requests}++;
	pack("CC", $stream, 4 * $sid) . $offset . $length . $r;
}

sub parse_int {
	my ($buf) = @_;
	my $val = unpack("C", substr($buf, 0, 1));
	my $len = my $plen = 1 << ($val >> 6);
	$val = $val & 0x3f;
	while (--$len) {
		$val = ($val << 8) + unpack("C", substr($buf, $plen - $len, 1))
	}
	return ($plen, $val);
}

sub build_int {
	my ($value) = @_;

	my $build_int_set = sub {
		my ($value, $len, $bits) = @_;
		(($value >> ($len * 8)) & 0xff) | ($bits << 6);
	};

	if ($value < 1 << 6) {
		pack("C", $build_int_set->($value, 0, 0));

	} elsif ($value < 1 << 14) {
		pack("C*",
			$build_int_set->($value, 1, 1),
			$build_int_set->($value, 0, 0),
		);

	} elsif ($value < 1 << 30) {
		pack("C*",
			$build_int_set->($value, 3, 2),
			$build_int_set->($value, 2, 0),
			$build_int_set->($value, 1, 0),
			$build_int_set->($value, 0, 0),
		);

	} else {
		pack("C*",
			build_int_set->($value, 7, 3),
			build_int_set->($value, 6, 0),
			build_int_set->($value, 5, 0),
			build_int_set->($value, 4, 0),
			build_int_set->($value, 3, 0),
			build_int_set->($value, 2, 0),
			build_int_set->($value, 1, 0),
			build_int_set->($value, 0, 0),
		);
	}
}

###############################################################################

sub read_stream_message {
	my ($self, $timo) = @_;
	my ($level, $plaintext, @data);
	my $s = $self->{socket};

	while (1) {
		@data = $self->parse_stream();
		return @data if $#data;
		return if scalar @{$self->{frames_in}};

		my $txt;

		if (!length($self->{buf})) {
			return unless IO::Select->new($s)->can_read($timo || 3);
			$s->sysread($self->{buf}, 65527);
			$txt = "recv";
		} else {
			$txt =  "remaining";
		}
		my $len = length $self->{buf};
		Test::Nginx::log_core('||', sprintf("$txt = [%d]", $len));

		while ($self->{buf}) {
			($level, $plaintext, $self->{buf}, $self->{token})
				= $self->decrypt_aead($self->{buf});
			return if !defined $plaintext;
			goto retry if $self->{token};
			$self->handle_frames(parse_frames($plaintext), $level);
			@data = $self->parse_stream();
			return @data if $#data;
			return if scalar @{$self->{frames_in}};
		}
	}
	return;
}

sub parse_stream {
	my ($self) = @_;
	my $data;

	for my $i (0 .. $#{$self->{stream_in}}) {
		my $stream = $self->{stream_in}[$i];
		next if !defined $stream;

		my $buf = $stream->{buf}[0][2];

		if ($stream->{buf}[0][3]) {
			$stream->{buf}[0][3] = 0;
			$stream->{eof} = 1;
			$data = '';
		}

		if (length($buf) > $stream->{pos}) {
			$data = substr($buf, $stream->{pos});
			$stream->{pos} = length($buf);
		}

		next if !defined $data;

		return ($i, $data, $stream->{eof} ? 1 : 0);
	}
}

###############################################################################

sub read_tls_message {
	my ($self, $buf, $type) = @_;
	my $s = $self->{socket};

	while (!$type->($self)) {
		my $txt;

		if (!length($$buf)) {
			return unless IO::Select->new($s)->can_read(3);
			$s->sysread($$buf, 65527);
			$txt = "recv";
		} else {
			$txt = "remaining";
		}
		my $len = length $$buf;
		Test::Nginx::log_core('||', sprintf("$txt = [%d]", $len));

		while ($$buf) {
			(my $level, my $plaintext, $$buf, $self->{token})
				= $self->decrypt_aead($$buf);
			return if !defined $plaintext;
			goto retry if $self->{token};
			$self->handle_frames(parse_frames($plaintext), $level);
			return 1 if $type->($self);
		}
	}
	return;
}

sub parse_tls_server_hello {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[0][0][2] if $self->{crypto_in}[0][0];
	return 0 if !$buf || length($buf) < 4;
	my $type = unpack("C", substr($buf, 0, 1));
	my $len = unpack("n", substr($buf, 2, 2));
	my $content = substr($buf, 4, $len);
	return 0 if length($content) < $len;
	$self->{tlsm}{sh} = substr($buf, 0, 4) . $content;
	return $self->{tlsm}{sh};
}

sub parse_tls_encrypted_extensions {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[2][0][2] if $self->{crypto_in}[2][0];
	return 0 if !$buf;
	my $off = 0;
	my $content;

	while ($off < length($buf)) {
		return 0 if length($buf) < 4;
		my $type = unpack("C", substr($buf, $off, 1));
		my $len = unpack("n", substr($buf, $off + 2, 2));
		$content = substr($buf, $off + 4, $len);
		return 0 if length($content) < $len;
		last if $type == 8;
		$off += 4 + $len;
	}
	$self->{tlsm}{ee} = substr($buf, $off, 4) . $content;
	return $self->{tlsm}{ee};
}

sub parse_tls_certificate {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[2][0][2] if $self->{crypto_in}[2][0];
	return 0 if !$buf;
	my $off = 0;
	my $content;

	while ($off < length($buf)) {
		return 0 if length($buf) < 4;
		my $type = unpack("C", substr($buf, $off, 1));
		my $len = unpack("n", substr($buf, $off + 2, 2));
		$content = substr($buf, $off + 4, $len);
		return 0 if length($content) < $len;
		last if $type == 11;
		$off += 4 + $len;
	}
	$self->{tlsm}{cert} = substr($buf, $off, 4) . $content;
	return $self->{tlsm}{cert};
}

sub parse_tls_certificate_verify {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[2][0][2] if $self->{crypto_in}[2][0];
	return 0 if !$buf;
	my $off = 0;
	my $content;

	while ($off < length($buf)) {
		return 0 if length($buf) < 4;
		my $type = unpack("C", substr($buf, $off, 1));
		my $len = unpack("n", substr($buf, $off + 2, 2));
		$content = substr($buf, $off + 4, $len);
		return 0 if length($content) < $len;
		last if $type == 15;
		$off += 4 + $len;
	}
	$self->{tlsm}{cv} = substr($buf, $off, 4) . $content;
	return $self->{tlsm}{cv};
}

sub parse_tls_finished {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[2][0][2] if $self->{crypto_in}[2][0];
	return 0 if !$buf;
	my $off = 0;
	my $content;

	while ($off < length($buf)) {
		return 0 if length($buf) < 4;
		my $type = unpack("C", substr($buf, $off, 1));
		my $len = unpack("n", substr($buf, $off + 2, 2));
		$content = substr($buf, $off + 4, $len);
		return 0 if length($content) < $len;
		last if $type == 20;
		$off += 4 + $len;
	}
	$self->{tlsm}{sf} = substr($buf, $off, 4) . $content;
	return $self->{tlsm}{sf};
}

sub parse_tls_nst {
	my ($self) = @_;
	my $buf = $self->{crypto_in}[3][0][2] if $self->{crypto_in}[3][0];
	return 0 if !$buf;
	my $off = 0;
	my $content;

	while ($off < length($buf)) {
		return 0 if length($buf) < 4;
		my $type = unpack("C", substr($buf, $off, 1));
		my $len = unpack("n", substr($buf, $off + 2, 2));
		$content = substr($buf, $off + 4, $len);
		return 0 if length($content) < $len;
		$self->{tlsm}{nst} .= substr($buf, $off, 4) . $content;
		$self->save_session_tickets(substr($buf, $off, 4) . $content);
		$off += 4 + $len;
		substr($self->{crypto_in}[3][0][2], 0, $off) = '';
	}
}

sub build_tls_client_hello {
	my ($self) = @_;
	my $key_share = $self->{sk}->export_key_raw('public');

	my $version = "\x03\x03";
	my $random = Crypt::PRNG::random_bytes(32);
	my $session = "\x00";
	my $cipher = "\x00\x02\x13\x01";
	my $compr = "\x01\x00";
	my $ext = build_tlsext_server_name($self->{sni})
		. build_tlsext_supported_groups(29)
		. build_tlsext_alpn("h3", "hq-interop")
		. build_tlsext_sigalgs(0x0804, 0x0805, 0x0806)
		. build_tlsext_supported_versions(0x0304)
		. build_tlsext_ke_modes(1)
		. build_tlsext_key_share(29, $key_share)
		. build_tlsext_quic_tp($self->{scid}, $self->{opts});

	$ext .= build_tlsext_early_data($self->{psk})
		. build_tlsext_psk($self->{psk}) if keys %{$self->{psk}};

	my $len = pack('n', length($ext));
	my $ch = $version . $random . $session . $cipher . $compr . $len . $ext;
	$ch = "\x01\x00" . pack('n', length($ch)) . $ch;
	$ch = build_tls_ch_with_binder($ch, $self->{es_prk})
		if keys %{$self->{psk}};
	return $ch;
}

sub build_tlsext_server_name {
	my ($name) = @_;
	my $sname = pack('xn', length($name)) . $name;
	my $snamelist = pack('n', length($sname)) . $sname;
	pack('n2', 0, length($snamelist)) . $snamelist;
}

sub build_tlsext_supported_groups {
	my $ngrouplist = pack('n*', @_ * 2, @_);
	pack('n2', 10, length($ngrouplist)) . $ngrouplist;
}

sub build_tlsext_alpn {
	my $protoname = pack('(C/a*)*', @_);
	my $protonamelist = pack('n', length($protoname)) . $protoname;
	pack('n2', 16, length($protonamelist)) . $protonamelist;
}

sub build_tlsext_sigalgs {
	my $sschemelist = pack('n*', @_ * 2, @_);
	pack('n2', 13, length($sschemelist)) . $sschemelist;
}

sub build_tlsext_supported_versions {
	my $versions = pack('Cn*', @_ * 2, @_);
	pack('n2', 43, length($versions)) . $versions;
}

sub build_tlsext_ke_modes {
	my $versions = pack('C*', scalar(@_), @_);
	pack('n2', 45, length($versions)) . $versions;
}

sub build_tlsext_key_share {
	my ($group, $share) = @_;
	my $kse = pack("n2", $group, length($share)) . $share;
	my $ksch = pack("n", length($kse)) . $kse;
	pack('n2', 51, length($ksch)) . $ksch;
}

sub build_tlsext_quic_tp {
	my ($scid, $opts) = @_;
	my $tp = '';
	my $quic_tp_tlv = sub {
		my ($id, $val) = @_;
		$val = $opts->{$id} // $val;
		$val = build_int($val) unless $id == 15;
		$tp .= build_int($id) . pack("C*", length($val)) . $val;
	};
	$quic_tp_tlv->(1, 30000);
	$quic_tp_tlv->(4, 1048576);
	$quic_tp_tlv->(5, 262144);
	$quic_tp_tlv->(7, 262144);
	$quic_tp_tlv->(9, 100);
	$quic_tp_tlv->(15, $scid);
	pack('n2', 57, length($tp)) . $tp;
}

sub build_tlsext_early_data {
	my ($psk) = @_;
	$psk->{ed} ? pack('n2', 42, 0) : '';
}

sub build_tlsext_psk {
	my ($psk) = @_;
	my $identity = pack('n', length($psk->{ticket})) . $psk->{ticket}
		. $psk->{age_add};
	my $identities = pack('n', length($identity)) . $identity;
	my $hash = pack('x32'); # SHA256
	my $binder = pack('C', length($hash)) . $hash;
	my $binders = pack('n', length($binder)) . $binder;
	pack('n2', 41, length($identities . $binders)) . $identities . $binders;
}

sub build_tls_ch_with_binder {
	my ($ch, $prk) = @_;
	my $digest0 = Crypt::Digest::digest_data('SHA256', '');
	my $key = hkdf_expand_label("tls13 res binder", 32, $prk, $digest0);
	my $truncated = substr($ch, 0, -35);
	my $context = Crypt::Digest::digest_data('SHA256', $truncated);
	$truncated . binders($key, $context);
}

###############################################################################

1;

###############################################################################
