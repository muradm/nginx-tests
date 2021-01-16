#!/usr/bin/perl

# Tests for imap/pop3/smtp proxy protocol handling.
# Note: testing only v1 protocol here with hope that v2 is tested by core

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;
use Test::Nginx::POP3;
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/mail imap pop3 smtp/)->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  http://127.0.0.1:8080; # unused

    server {
        listen     127.0.0.1:8143 proxy_protocol;
        protocol   imap;
    }

    server {
        listen     127.0.0.1:8110 proxy_protocol;
        protocol   pop3;
    }

    server {
        listen     127.0.0.1:8025 proxy_protocol;
        protocol   smtp;
    }
}

EOF

$t->run();

###############################################################################

# imap, proxy protocol handler

my $s = Test::Nginx::IMAP->new(PeerAddr => '127.0.0.1:' . port(8143));
$s->send('PROXY TCP4 192.168.1.10 192.168.1.1 18143 8143');
$s->read();

$s->send('1 CAPABILITY');
$s->check(qr/^\* CAPABILITY IMAP4 IMAP4rev1 UIDPLUS AUTH=PLAIN/, 'imap proxy protocol');
$s->ok('imap proxy protocol handler');

###############################################################################

# pop3, proxy protocol handler

$s = Test::Nginx::POP3->new(PeerAddr => '127.0.0.1:' . port(8110));
$s->send('PROXY TCP4 192.168.1.10 192.168.1.1 18143 8110');
$s->read();

$s->send('CAPA');
$s->ok('pop3 capa');

my $caps = get_auth_caps($s);
like($caps, qr/USER/, 'pop3 - user');
like($caps, qr/TOP:USER:UIDL:SASL PLAIN LOGIN/, 'pop3 - methods');
unlike($caps, qr/STLS/, 'pop3 - no stls');

###############################################################################

# smtp, proxy protocol handler

$s = Test::Nginx::SMTP->new(PeerAddr => '127.0.0.1:' . port(8025));
$s->send('PROXY TCP4 192.168.1.10 192.168.1.1 18143 8110');
$s->read();

$s->send('EHLO example.com');
$s->check(qr/^250 AUTH PLAIN LOGIN\x0d\x0a?/, 'smtp ehlo');

###############################################################################

sub get_auth_caps {
	my ($s) = @_;
	my @meth;

	while ($s->read()) {
		last if /^\./;
		push @meth, $1 if /(.*?)\x0d\x0a?/ms;
	}
	join ':', @meth;
}

###############################################################################
