use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv write_dnsapi_stub $TMPDIR);

# ===========================================================================
# Multi-provider / multi-account mode (commit 6c12bbf)
#
# $config is read once at require-time, so a single .t file exercises exactly
# one mode. This file drives the multi-provider path; legacy single-provider
# behaviour is covered in 20-acme_cmd.t.
# ===========================================================================

my $mp_config = {
    acmesh_extra_params_install      => [],
    acmesh_extra_params_install_cert => [],
    acmesh_extra_params_issue        => [],
    email        => 'test@example.com',
    # Global dns_provider/env are legacy fields. In multi-provider mode they
    # must NOT leak into challenge calls (only self-cert generation uses them).
    dns_provider => 'dns_test',
    env          => { 'GLOBAL_TOKEN' => 'should-not-leak' },
    hostname     => 'test.example.com',
    bind         => '*:0',
    auth         => [{ user => 'bob', pass => 'dobbs', host => 'example.com' }],
    providers    => [
        {
            name         => 'provider-a',
            dns_provider => 'dns_a',
            # 'shared.example.com' is intentionally listed by BOTH providers
            # to exercise first-match-wins (provider-a is declared first).
            domains      => ['a.example.com', 'shared.example.com'],
            env          => { 'A_TOKEN' => 'aaa' },
        },
        {
            name         => 'provider-b',
            dns_provider => 'dns_b',
            domains      => ['b.example.com', 'shared.example.com'],
            env          => { 'B_TOKEN' => 'bbb' },
        },
    ],
};

my $tmp = setup_testenv(config => $mp_config);

# Both provider scripts must exist before require: the boot-time sanity check
# dies if any provider's dnsapi script is missing. Each stub logs all three
# tokens on every call so a single log line reveals both which provider ran
# and which env vars were in scope for it.
write_dnsapi_stub('dns_a', 'A_TOKEN', 'B_TOKEN', 'GLOBAL_TOKEN');
write_dnsapi_stub('dns_b', 'A_TOKEN', 'B_TOKEN', 'GLOBAL_TOKEN');

require "$FindBin::Bin/../acmeproxy.pl";
AcmeProxyTest::silence_logg();

sub call_log {
    my $path = "$TMPDIR/.acme.sh/calls.log";
    return '' unless -f $path;
    open my $fh, '<', $path or die $!;
    local $/;
    return scalar <$fh>;
}
sub clear_calls { unlink "$TMPDIR/.acme.sh/calls.log" }

# --- fqdn_matches_domain ---------------------------------------------------
ok( main::fqdn_matches_domain('example.com', 'example.com'),
    'exact match');
ok( main::fqdn_matches_domain('foo.example.com', 'example.com'),
    'subdomain matches parent domain');
ok( main::fqdn_matches_domain('a.b.c.example.com', 'example.com'),
    'deep subdomain matches');
ok( !main::fqdn_matches_domain('example.org', 'example.com'),
    'different domain does not match');
# Label-boundary safety: a substring match would wrongly accept this. The
# regex requires a '.' before the suffix, so it must be rejected.
ok( !main::fqdn_matches_domain('notexample.com', 'example.com'),
    'prefix that is not a label boundary does not match');
ok( !main::fqdn_matches_domain('example.com', 'foo.example.com'),
    'fqdn shorter than domain does not match');
# Trailing dots are stripped on both arguments before comparison.
ok( main::fqdn_matches_domain('foo.example.com.', 'example.com'),
    'trailing dot on fqdn normalized');
ok( main::fqdn_matches_domain('foo.example.com', 'example.com..'),
    'trailing dots on domain normalized');

# --- get_provider_config_for_fqdn ------------------------------------------
my $p = main::get_provider_config_for_fqdn('_acme-challenge.a.example.com');
is($p->{name}, 'provider-a', 'a.example.com routes to provider-a');
is($p->{dns_provider}, 'dns_a', 'provider-a carries its own dns_provider');

$p = main::get_provider_config_for_fqdn('b.example.com');
is($p->{name}, 'provider-b', 'b.example.com routes to provider-b');

# Both providers claim shared.example.com; the first one declared wins.
$p = main::get_provider_config_for_fqdn('host.shared.example.com');
is($p->{name}, 'provider-a', 'overlapping domain resolves to first match');

# Trailing dot must not defeat provider selection.
$p = main::get_provider_config_for_fqdn('a.example.com.');
is($p->{name}, 'provider-a', 'trailing dot still selects provider-a');

# No provider owns this suffix -> dies (acme_cmd turns this into a 500).
eval { main::get_provider_config_for_fqdn('orphan.example.org') };
like($@, qr/No provider configured for domain/,
    'unmatched fqdn dies with a clear message');

# --- acme_cmd: provider routing + env scoping ------------------------------
# Sequencing matters: provider-a runs BEFORE provider-b in the same process.
# That ordering is what gives the env-isolation assertion teeth -- if acme_cmd
# dropped `local %ENV`, provider-a's A_TOKEN would still be set when provider-b
# runs, and the provider-b log line below would show A_TOKEN=aaa.
clear_calls();
my $res = main::acme_cmd('add', '_acme-challenge.a.example.com', 'tok');
is($res->{status}, 200, 'add for provider-a domain succeeds');
my $log = call_log();
like($log, qr/^dns_a add _acme-challenge\.a\.example\.com tok /m,
    'provider-a fqdn dispatched to dns_a');
like($log, qr/A_TOKEN=aaa\b/, "provider-a's A_TOKEN is set during its call");
like($log, qr/\bB_TOKEN=(?:\s|$)/m, "provider-b's B_TOKEN absent during provider-a call");
like($log, qr/\bGLOBAL_TOKEN=(?:\s|$)/m,
    'legacy global env does NOT leak in multi-provider mode');

clear_calls();
$res = main::acme_cmd('add', '_acme-challenge.b.example.com', 'tok');
is($res->{status}, 200, 'add for provider-b domain succeeds');
$log = call_log();
like($log, qr/^dns_b add _acme-challenge\.b\.example\.com tok /m,
    'provider-b fqdn dispatched to dns_b');
like($log, qr/B_TOKEN=bbb\b/, "provider-b's B_TOKEN is set during its call");
like($log, qr/\bA_TOKEN=(?:\s|$)/m,
    "provider-a's A_TOKEN did not leak into provider-b call (local %ENV)");

# First-match-wins also holds end-to-end through acme_cmd.
clear_calls();
$res = main::acme_cmd('add', 'host.shared.example.com', 'tok');
is($res->{status}, 200, 'add for overlapping domain succeeds');
like(call_log(), qr/^dns_a /m, 'overlapping domain dispatched to first provider (dns_a)');

# rm dispatches the same way.
clear_calls();
$res = main::acme_cmd('rm', '_acme-challenge.b.example.com', 'tok');
is($res->{status}, 200, 'rm for provider-b domain succeeds');
like(call_log(), qr/^dns_b rm /m, 'rm dispatched to dns_b');

# --- acme_cmd: no matching provider ----------------------------------------
clear_calls();
$res = main::acme_cmd('add', 'orphan.example.org', 'tok');
is($res->{status}, 500, 'unmatched fqdn returns 500');
like($res->{text}, qr/provider selection failed/, 'text reports provider selection failure');
is($res->{json}{error}, 'provider selection failed', 'json reports provider selection failure');
is(call_log(), '', 'no dnsapi invoked when no provider matches');

# --- env restoration in the parent process ---------------------------------
# acme_cmd scopes provider env with `local %ENV`, so nothing it set survives
# the call. (In multi-provider mode these are never set globally either.)
ok(!exists $ENV{A_TOKEN}, 'A_TOKEN not left set after acme_cmd returns');
ok(!exists $ENV{B_TOKEN}, 'B_TOKEN not left set after acme_cmd returns');

done_testing();
