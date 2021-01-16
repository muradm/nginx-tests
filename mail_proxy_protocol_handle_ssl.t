#!/usr/bin/perl

# Tests for mail proxy protocol handler with ssl.
# Note: testing only v1 protocol here with hope that v2 is tested by core

###############################################################################

use warnings;
use strict;

use Socket qw/ CRLF /;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval {
	require Net::SSLeay;
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
};
plan(skip_all => 'Net::SSLeay not installed') if $@;

my $t = Test::Nginx->new()->has(qw/mail mail_ssl imap pop3 smtp/)
	->has_daemon('openssl')->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  http://127.0.0.1:8080; # unused

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
    ssl_session_tickets off;

    ssl_password_file password;

    ssl_session_cache none;

    server {
        listen             127.0.0.1:8993 ssl;
        protocol           imap;
    }

    server {
        listen             127.0.0.1:8994 ssl proxy_protocol;
        protocol           imap;
    }

    server {
        listen             127.0.0.1:8995 ssl;
        protocol           pop3;
    }

    server {
        listen             127.0.0.1:8996 ssl proxy_protocol;
        protocol           pop3;
    }

    server {
        listen             127.0.0.1:8465 ssl;
        protocol           smtp;
    }

    server {
        listen             127.0.0.1:8466 ssl proxy_protocol;
        protocol           smtp;
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

foreach my $name ('localhost', 'inherits') {
	system("openssl genrsa -out $d/$name.key -passout pass:localhost "
		. "-aes128 2048 >>$d/openssl.out 2>&1") == 0
		or die "Can't create private key: $!\n";
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt "
		. "-key $d/$name.key -passin pass:localhost"
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

my $ctx = Net::SSLeay::CTX_new() or die("Failed to create SSL_CTX $!");
$t->write_file('password', 'localhost');

open OLDERR, ">&", \*STDERR; close STDERR;
$t->run();
open STDERR, ">&", \*OLDERR;

###############################################################################

my @list = (qw(8993 8994 8995 8996 8465 8466));

while (my ($p1, $p2) = splice (@list,0,2)) {
    my ($s, $ssl, $ses);

    $s = get_socket($p1);

    $ssl = make_ssl_socket($s);
    $ses = Net::SSLeay::get_session($ssl);
    like(Net::SSLeay::dump_peer_certificate($ssl), qr/CN=localhost/, 'CN');

    $s = get_socket($p2);
    $s->print('PROXY TCP4 192.168.1.10 192.168.1.1 18143 8110' . CRLF);

    $ssl = make_ssl_socket($s);
    $ses = Net::SSLeay::get_session($ssl);
    like(Net::SSLeay::dump_peer_certificate($ssl), qr/CN=localhost/, 'CN');
}

###############################################################################

sub get_socket {
	my ($port) = @_;
    return IO::Socket::INET->new('127.0.0.1:' . port($port));
}

sub make_ssl_socket {
	my ($socket, $ses) = @_;

	my $ssl = Net::SSLeay::new($ctx) or die("Failed to create SSL $!");
	Net::SSLeay::set_session($ssl, $ses) if defined $ses;
	Net::SSLeay::set_fd($ssl, fileno($socket));
	Net::SSLeay::connect($ssl) or die("ssl connect");
	return $ssl;
}

###############################################################################
