#!/usr/bin/perl

# Tests for nginx mail proxy module, the proxy_protocol directive.

###############################################################################

use warnings;
use strict;

use Socket qw/ CRLF /;

use Test::More;

use MIME::Base64;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail smtp http rewrite/)->plan(9);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
    worker_connections 48;
}

mail {
    auth_http  http://127.0.0.1:8080/mail/auth;
    smtp_auth  login plain external;

    server {
        listen     127.0.0.1:8025;
        protocol   smtp;
        xclient    off;
    }

    server {
        listen     127.0.0.1:8027;
        protocol   smtp;
        xclient    off;
        proxy_protocol on;
    }

    server {
        listen     127.0.0.1:8029 proxy_protocol;
        protocol   smtp;
        xclient    off;
        proxy_protocol on;
        proxy_smtp_auth on;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /mail/auth {
            add_header Auth-Status OK;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port   %%PORT_8026%%;
            add_header Auth-User   test@example.com;
            add_header Auth-Pass   test@example.com;
            return 204;
        }
    }
}

EOF

$t->run();

###############################################################################

my ($s, $pp_data);

# no proxy_protocol in or out

$t->run_daemon(\&smtp_test_listener, port(8026));
$t->waitforsocket('127.0.0.1:' . port(8026));

$s = Test::Nginx::SMTP->new(PeerAddr => '127.0.0.1:' . port(8025));
$s->check(qr/ESMTP ready/);
$s->send('EHLO example.com');
$s->check(qr/250 AUTH PLAIN LOGIN EXTERNAL/);
$s->send('AUTH PLAIN ' . encode_base64("\0test\@example.com\0secret", ''));
$s->authok('ehlo, auth');
$t->stop_daemons();

# proxy_protocol only out

$pp_data = 'PROXY TCP4 192.168.1.10 192.168.1.11';
$t->run_daemon(\&smtp_test_listener, port(8026), $pp_data);
$t->waitforsocket('127.0.0.1:' . port(8026));

$s = Test::Nginx::SMTP->new(PeerAddr => '127.0.0.1:' . port(8027));
$s->check(qr/ESMTP ready/);
$s->send('EHLO example.com');
$s->check(qr/250 AUTH PLAIN LOGIN EXTERNAL/);
$s->send('AUTH PLAIN ' . encode_base64("\0test\@example.com\0secret", ''));
$s->authok('ehlo, auth');
$t->stop_daemons();

# proxy_protocol only out and in
$pp_data = 'PROXY TCP4 192.168.1.10 192.168.1.11';
$t->run_daemon(\&smtp_test_listener, port(8026), $pp_data);
$t->waitforsocket('127.0.0.1:' . port(8026));

$s = Test::Nginx::SMTP->new(PeerAddr => '127.0.0.1:' . port(8029));
$s->send($pp_data . ' 51298 8027');
$s->check(qr/ESMTP ready/);
$s->send('EHLO example.com');
$s->check(qr/250 AUTH PLAIN LOGIN EXTERNAL/);
$s->send('AUTH PLAIN ' . encode_base64("\0test\@example.com\0secret", ''));
$s->authok('ehlo, auth');
$t->stop_daemons();


###############################################################################

sub smtp_test_listener {
	my ($port, $expected) = @_;
    my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . ($port || port(8026)),
		Listen => 5,
        Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        if (defined($expected)) {
            $expected = $expected . CRLF;
            while (<$client>) {
                if (/^proxy/i) {
                    Test::Nginx::log_core('||>>', $_);
                    last;
                }
            }
        }

        sub send_client {
            my ($c, $d) = @_;
            Test::Nginx::log_core('||<<', $d);
            print $c $d . CRLF;
        }

        print $client "220 fake esmtp server ready" . CRLF;

        while (<$client>) {
            Test::Nginx::log_core('||>>', $_);

            my $res = '';

            if (/^quit/i) {
                send_client($client, '221 quit ok');
            } elsif (/^(ehlo|helo)/i) {
                send_client($client, '250-ok');
                send_client($client, '250 AUTH PLAIN LOGIN EXTERNAL');
            } elsif (/^rset/i) {
                send_client($client, '250 rset ok');
            } elsif (/^auth plain/i) {
                send_client($client, '235 auth ok');
            } elsif (/^mail from:[^@]+$/i) {
                send_client($client, '500 mail from error');
            } elsif (/^mail from:/i) {
                send_client($client, '250 mail from ok');
            } elsif (/^rcpt to:[^@]+$/i) {
                send_client($client, '500 rcpt to error');
            } elsif (/^rcpt to:/i) {
                send_client($client, '250 rcpt to ok');
            } else {
                send_client($client, '500 unknown command');
            }
        }

		close $client;
    }
}

###############################################################################
