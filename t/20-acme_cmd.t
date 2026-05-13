use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv $TMPDIR);

my $tmp = setup_testenv();
require "$FindBin::Bin/../acmeproxy.pl";
AcmeProxyTest::silence_logg();

# --- fqdn validation -------------------------------------------------------
my @metachars = (';', '$', '`', ' ', '|', '&', '<', '>', "\n", '"', "'", '(', ')');
for my $c (@metachars) {
    my $label = $c eq "\n" ? 'newline' : "'$c'";
    my $res = main::acme_cmd('add', "foo${c}bar.example.com", 'tok');
    is($res->{status}, 400, "fqdn with $label rejected");
    like($res->{text}, qr/invalid characters in fqdn/, "fqdn $label error text");
}

# --- value validation ------------------------------------------------------
for my $c (@metachars) {
    my $label = $c eq "\n" ? 'newline' : "'$c'";
    my $res = main::acme_cmd('add', 'foo.example.com', "tok${c}bad");
    is($res->{status}, 400, "value with $label rejected");
    like($res->{text}, qr/invalid characters in value/, "value $label error text");
}

# --- happy path ------------------------------------------------------------
my $res = main::acme_cmd('add', '_acme-challenge.bob.example.com', 'token123');
is($res->{status}, 200, 'valid add returns 200');
like($res->{text}, qr/^success: _acme-challenge\.bob\.example\.com "token123"$/,
    'text response is "success: <fqdn> \"<value>\""');
is_deeply($res->{json},
    { fqdn => '_acme-challenge.bob.example.com', value => 'token123' },
    'json response is {fqdn, value} dict');

# --- trailing-dot normalization -------------------------------------------
# text uses stripped fqdn; json preserves the caller's exact input
$res = main::acme_cmd('add', '_acme-challenge.bob.example.com.', 'tok');
like($res->{text}, qr/^success: _acme-challenge\.bob\.example\.com "tok"$/,
    'text uses fqdn with trailing dots stripped');
is($res->{json}{fqdn}, '_acme-challenge.bob.example.com.',
    'json preserves caller fqdn with its trailing dot');

$res = main::acme_cmd('add', '_acme-challenge.bob.example.com...', 'tok');
like($res->{text}, qr/^success: _acme-challenge\.bob\.example\.com "tok"$/,
    'text strips multiple trailing dots');

# --- rm action -------------------------------------------------------------
$res = main::acme_cmd('rm', '_acme-challenge.bob.example.com', 'token123');
is($res->{status}, 200, 'rm returns 200');

# --- failure path ----------------------------------------------------------
{
    local $ENV{ACMEPROXY_TEST_FAIL} = 1;
    $res = main::acme_cmd('add', '_acme-challenge.bob.example.com', 'tok');
    is($res->{status}, 500, 'dnsapi failure returns 500');
    like($res->{text}, qr/check acmeproxy\.pl logs/, '500 error message text');
}

# --- call log inspection ---------------------------------------------------
# The stub dns_test.sh appends "add|rm <fqdn> <value>" lines to calls.log.
# After the happy-path runs above, the log should contain at least one add
# and one rm.
my $log_path = "$tmp/.acme.sh/calls.log";
ok(-f $log_path, 'calls.log exists');
my $content = do { open my $fh, '<', $log_path or die $!; local $/; <$fh> };
like($content, qr/^add /m, 'add invocation recorded');
like($content, qr/^rm /m,  'rm invocation recorded');

# Arguments passed to the stub are positional ($1, $2) so they cannot
# be parsed as shell syntax. Confirm the FQDN ended up as a literal arg.
like($content, qr/_acme-challenge\.bob\.example\.com token123/,
    'fqdn and value reach dnsapi as positional args');

done_testing();
