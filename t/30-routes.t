use strict;
use warnings;
use Test::More;
use Test::Mojo;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv clear_log @LOG_LINES $TMPDIR);
use MIME::Base64 qw(encode_base64);

my $tmp = setup_testenv();
require "$FindBin::Bin/../acmeproxy.pl";
AcmeProxyTest::silence_logg();

my $t = Test::Mojo->new(main::app());

sub basic {
    my ($user, $pass) = @_;
    return 'Basic ' . encode_base64("$user:$pass", '');
}

sub call_log {
    my $path = "$TMPDIR/.acme.sh/calls.log";
    return '' unless -f $path;
    open my $fh, '<', $path or die $!;
    local $/;
    return scalar <$fh>;
}

sub clear_calls {
    unlink "$TMPDIR/.acme.sh/calls.log";
}

# --- catch-all -------------------------------------------------------------
# Note: the script uses any '/*' which requires at least one path segment;
# bare GET / does not match it (returns 404).
$t->get_ok('/anything')->status_is(200)->content_like(qr/not a teapot/);
$t->get_ok('/foo/bar/baz')->status_is(200)->content_like(qr/not a teapot/);
$t->get_ok('/')->status_is(404);

# --- invalid JSON ----------------------------------------------------------
$t->post_ok('/present', 'this is not json')
    ->status_is(400)
    ->content_like(qr/Invalid JSON/);

# /present with valid JSON but no auth -> 401, WWW-Authenticate set
$t->post_ok('/present' => json => { fqdn => 'foo.bob.example.com', value => 'tok' })
    ->status_is(401)
    ->content_like(qr/Invalid credentials/)
    ->header_like('WWW-Authenticate', qr/Basic/);

# --- bad credentials -------------------------------------------------------
clear_log();
$t->post_ok('/present' => { Authorization => basic('bob', 'wrong') }
                       => json => { fqdn => 'foo.bob.example.com', value => 'tok' })
    ->status_is(401);
ok((grep { /auth: Invalid credentials for user bob/ } @LOG_LINES),
   'bad creds audit log present')
    or diag explain \@LOG_LINES;

# Unknown user
$t->post_ok('/present' => { Authorization => basic('mallory', 'x') }
                       => json => { fqdn => 'foo.bob.example.com', value => 'tok' })
    ->status_is(401);

# --- happy path: /present --------------------------------------------------
clear_calls();
clear_log();
$t->post_ok('/present' => { Authorization => basic('bob', 'dobbs') }
                       => json => { fqdn => '_acme-challenge.bob.example.com', value => 'tok' })
    ->status_is(200)
    ->content_like(qr/"fqdn":\s*"_acme-challenge\.bob\.example\.com\."/)
    ->content_like(qr/"value":\s*"tok"/);
ok((grep { /auth: bob successfully authenticated/ } @LOG_LINES),
   'success audit log present')
    or diag explain \@LOG_LINES;

# Confirms the script invokes dnsapi twice for /present: rm then add.
my @lines = grep { length } split /\n/, call_log();
is(scalar @lines, 2, '/present invokes dnsapi twice (rm then add)')
    or diag explain \@lines;
like($lines[0], qr/^rm /,  'first dnsapi call is rm (clear stale)');
like($lines[1], qr/^add /, 'second dnsapi call is add');

# --- happy path: /cleanup --------------------------------------------------
clear_calls();
$t->post_ok('/cleanup' => { Authorization => basic('bob', 'dobbs') }
                       => json => { fqdn => '_acme-challenge.bob.example.com', value => 'tok' })
    ->status_is(200)
    ->content_like(qr/"fqdn":\s*"_acme-challenge\.bob\.example\.com\."/);

@lines = grep { length } split /\n/, call_log();
is(scalar @lines, 1, '/cleanup invokes dnsapi once (rm only)');
like($lines[0], qr/^rm /, 'cleanup call is rm');

# --- host-scoped denial ----------------------------------------------------
$t->post_ok('/present' => { Authorization => basic('bob', 'dobbs') }
                       => json => { fqdn => 'foo.alice.example.com', value => 'tok' })
    ->status_is(401);

# --- failure propagation --------------------------------------------------
{
    local $ENV{ACMEPROXY_TEST_FAIL} = 1;
    $t->post_ok('/present' => { Authorization => basic('bob', 'dobbs') }
                           => json => { fqdn => '_acme-challenge.bob.example.com', value => 'tok' })
        ->status_is(500)
        ->content_like(qr/check acmeproxy\.pl logs/);
    $t->post_ok('/cleanup' => { Authorization => basic('bob', 'dobbs') }
                           => json => { fqdn => '_acme-challenge.bob.example.com', value => 'tok' })
        ->status_is(500);
}

# --- shell injection attempts ---------------------------------------------
# An authenticated user still cannot smuggle shell syntax through fqdn/value.
# The fqdn here ends with .bob.example.com so it passes auth's host regex,
# but acme_cmd's [\w_.-]+ check rejects the embedded ';'.
$t->post_ok('/present' => { Authorization => basic('bob', 'dobbs') }
                       => json => { fqdn => 'foo;.bob.example.com', value => 'tok' })
    ->status_is(400)
    ->content_like(qr/invalid characters in fqdn/);
$t->post_ok('/present' => { Authorization => basic('bob', 'dobbs') }
                       => json => { fqdn => 'foo.bob.example.com', value => 'tok`id`' })
    ->status_is(400)
    ->content_like(qr/invalid characters in value/);

done_testing();
