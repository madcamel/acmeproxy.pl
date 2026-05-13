use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv clear_log @LOG_LINES);

setup_testenv();
require "$FindBin::Bin/../acmeproxy.pl";
AcmeProxyTest::silence_logg();

# --- negative paths --------------------------------------------------------
ok(!main::check_auth(undef, 'foo.bob.example.com'), 'undef userinfo rejected');
ok(!main::check_auth('',    'foo.bob.example.com'), 'empty userinfo rejected');
ok(!main::check_auth('mallory:x',  'foo.bob.example.com'), 'unknown user rejected');
ok(!main::check_auth('bob:wrong',  'foo.bob.example.com'), 'wrong password rejected');

# --- positive paths --------------------------------------------------------
# acme.sh sends FQDNs like "_acme-challenge.<host>" — any subdomain of the
# configured host satisfies the /\.HOST\.?$/ regex
ok( main::check_auth('bob:dobbs', 'foo.bob.example.com'),
    'subdomain match for bob');
ok( main::check_auth('bob:dobbs', '_acme-challenge.bob.example.com'),
    'acme-challenge prefix matches');
ok( main::check_auth('bob:dobbs', '_acme-challenge.bob.example.com.'),
    'trailing-dot FQDN still matches');

# --- host scoping ----------------------------------------------------------
ok(!main::check_auth('bob:dobbs',     'foo.alice.example.com'),
    'bob cannot issue for alice host');
ok(!main::check_auth('bob:dobbs',     'evil.com'),
    'bob cannot issue for unrelated domain');
ok(!main::check_auth('bob:dobbs',     'foobob.example.com'),
    'host match requires preceding dot (no substring sneak)');
ok( main::check_auth('alice:rabbit', 'foo.alice.example.com'),
    'alice can issue for alice subdomain');
ok(!main::check_auth('alice:rabbit', 'foo.bob.example.com'),
    'alice cannot issue for bob subdomain');

# --- multi-host single user -----------------------------------------------
push @{ main::app()->config->{auth} },
    { user => 'bob', pass => 'dobbs', host => 'subgenius.example.com' };
ok( main::check_auth('bob:dobbs', 'foo.subgenius.example.com'),
    'bob authorized for second host entry');
ok( main::check_auth('bob:dobbs', 'foo.bob.example.com'),
    'bob still authorized for first host entry');

# --- audit log -------------------------------------------------------------
clear_log();
main::check_auth('bob:wrong', 'foo.bob.example.com');
ok( (grep { /auth: Invalid credentials for user bob/ } @LOG_LINES),
    'invalid creds logged for audit')
    or diag explain \@LOG_LINES;

clear_log();
main::check_auth('bob:dobbs', 'foo.bob.example.com');
ok( (grep { /auth: bob successfully authenticated/ } @LOG_LINES),
    'successful auth logged for audit')
    or diag explain \@LOG_LINES;

clear_log();
main::check_auth(undef, 'foo.bob.example.com');
ok( (grep { /credentials not supplied/ } @LOG_LINES),
    'missing creds logged for audit')
    or diag explain \@LOG_LINES;

# --- bcrypt (skipped when Crypt::Bcrypt unavailable) ----------------------
SKIP: {
    skip 'Crypt::Bcrypt not installed', 3
        unless eval { require Crypt::Bcrypt; Crypt::Bcrypt->import('bcrypt'); 1 };

    # Generate a real hash for password "carrot" at cost 4 (fast)
    my $hash = Crypt::Bcrypt::bcrypt('carrot', '2b', 4, '0123456789012345');

    # Add a charlie entry that has BOTH pass and hash. With Crypt::Bcrypt
    # available, the hash path should win (per script's ternary at line 168).
    push @{ main::app()->config->{auth} }, {
        user => 'charlie',
        pass => 'ignored-because-hash-wins',
        hash => $hash,
        host => 'charlie.example.com',
    };

    ok( main::check_auth('charlie:carrot', 'foo.charlie.example.com'),
        'bcrypt: correct password authorizes');
    ok(!main::check_auth('charlie:wrong',  'foo.charlie.example.com'),
        'bcrypt: wrong password rejected');
    ok(!main::check_auth('charlie:ignored-because-hash-wins', 'foo.charlie.example.com'),
        'bcrypt: plaintext field ignored when hash is present');
}

done_testing();
