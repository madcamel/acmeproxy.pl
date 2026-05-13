use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv write_config_file);
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(cwd);

my $script = "$FindBin::Bin/../acmeproxy.pl";

# ===========================================================================
# In-process: backcompat defaults
# ===========================================================================
# Test file's single require gets used here for the minimal-config case.
setup_testenv(
    config => {
        # Deliberately omit acmesh_extra_params_* and keypair_directory.
        email        => 'test@example.com',
        dns_provider => 'dns_test',
        env          => {},
        hostname     => 'test.example.com',
        bind         => '*:0',
        auth         => [{ user => 'bob', pass => 'dobbs', host => 'bob.example.com' }],
    },
);
require $script;
AcmeProxyTest::silence_logg();

my $cfg = main::app()->config;
is_deeply($cfg->{acmesh_extra_params_install},      [], 'acmesh_extra_params_install default []');
is_deeply($cfg->{acmesh_extra_params_install_cert}, [], 'acmesh_extra_params_install_cert default []');
is_deeply($cfg->{acmesh_extra_params_issue},        [], 'acmesh_extra_params_issue default []');
is($cfg->{keypair_directory}, "$ENV{HOME}/.acme.sh", 'keypair_directory default is $HOME/.acme.sh');

# ===========================================================================
# Subprocess helpers
# ===========================================================================
sub run_script {
    my (%args) = @_;
    my $cwd    = $args{cwd}  or die "cwd required";
    my $envref = $args{env} || {};

    my $original = cwd();
    my $pid = open my $fh, '-|';
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        # child
        chdir $cwd or die "chdir $cwd: $!";
        for my $k (keys %$envref) { $ENV{$k} = $envref->{$k} }
        open STDERR, '>&', \*STDOUT or die "merge stderr: $!";
        exec $^X, $script;
        die "exec failed: $!";
    }
    my $out = do { local $/; <$fh> };
    close $fh;
    my $exit = $?;
    return ($out, $exit);
}

sub stub_acme_home {
    my $home = shift;
    make_path("$home/.acme.sh/dnsapi");
    open my $fh, '>', "$home/.acme.sh/acme.sh"; close $fh;
    open $fh, '>', "$home/.acme.sh/acmeproxy.pl.crt"; close $fh;
    open $fh, '>', "$home/.acme.sh/acmeproxy.pl.key"; close $fh;
    open $fh, '>', "$home/.acme.sh/dnsapi/dns_test.sh";
    print $fh "dns_test_add(){ return 0; }\ndns_test_rm(){ return 0; }\n";
    close $fh;
}

# ===========================================================================
# Subprocess: missing config file -> writes example and dies
# ===========================================================================
{
    my $home = tempdir(CLEANUP => 1);
    my $cwd  = tempdir(CLEANUP => 1);
    my ($out, $exit) = run_script(cwd => $cwd, env => { HOME => $home });
    isnt($exit, 0, 'script exits non-zero when config missing');
    like($out, qr/Example configuration file written/, 'die message printed');
    ok(-f "$cwd/acmeproxy.pl.conf", 'example config file written to cwd');
    my @stat = stat "$cwd/acmeproxy.pl.conf";
    is(($stat[2] & 07777), 0600, 'example config file mode is 0600');
}

# ===========================================================================
# Subprocess: DNS provider script missing -> dies
# ===========================================================================
{
    my $home = tempdir(CLEANUP => 1);
    stub_acme_home($home);
    # Remove the dns_test stub so dns_nope is the only configured provider
    # and intentionally absent.
    my $cwd = tempdir(CLEANUP => 1);
    write_config_file($cwd, {
        acmesh_extra_params_install      => [],
        acmesh_extra_params_install_cert => [],
        acmesh_extra_params_issue        => [],
        email        => 'test@example.com',
        dns_provider => 'dns_nope',
        env          => {},
        hostname     => 'test.example.com',
        bind         => '*:0',
        auth         => [{ user => 'bob', pass => 'dobbs', host => 'bob.example.com' }],
    });

    my ($out, $exit) = run_script(cwd => $cwd, env => { HOME => $home });
    isnt($exit, 0, 'script exits non-zero when dns provider missing');
    like($out, qr/acme dnslib provider not found: dns_nope/,
         'die message names the missing provider');
}

# ===========================================================================
# Subprocess: bcrypt hash configured but Crypt::Bcrypt unavailable -> dies
# ===========================================================================
# Two cases:
#   - Crypt::Bcrypt IS available on this box: need Test::Without::Module to
#     block it for the child process. Skip if that module isn't installed.
#   - Crypt::Bcrypt is NOT available: the child will fail to load it
#     naturally; no extra blocking needed.
SKIP: {
    my $bcrypt_available    = eval { require Crypt::Bcrypt; 1 };
    my $can_block_in_child  = eval { require Test::Without::Module; 1 };

    skip 'Crypt::Bcrypt is installed and Test::Without::Module is not — cannot block', 2
        if $bcrypt_available && !$can_block_in_child;

    my $home = tempdir(CLEANUP => 1);
    stub_acme_home($home);
    my $cwd = tempdir(CLEANUP => 1);
    write_config_file($cwd, {
        acmesh_extra_params_install      => [],
        acmesh_extra_params_install_cert => [],
        acmesh_extra_params_issue        => [],
        email        => 'test@example.com',
        dns_provider => 'dns_test',
        env          => {},
        hostname     => 'test.example.com',
        bind         => '*:0',
        auth         => [{
            user => 'bob',
            hash => '$2b$12$ZkfzP1DVcFHSXyrtMRXJR.Ny2fpSixG00oLI2iMkT3yArpzs/921u',
            host => 'bob.example.com',
        }],
    });

    my %env = (HOME => $home);
    $env{PERL5OPT} = '-MTest::Without::Module=Crypt::Bcrypt' if $bcrypt_available;

    my ($out, $exit) = run_script(cwd => $cwd, env => \%env);
    isnt($exit, 0, 'script exits non-zero on bcrypt hash without Crypt::Bcrypt');
    like($out, qr/Crypt::Bcrypt is not available/,
         'die message names the missing module');
}

done_testing();
