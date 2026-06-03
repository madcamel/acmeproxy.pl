package AcmeProxyTest;
use strict;
use warnings;
use feature 'say';

use Exporter 'import';
our @EXPORT_OK = qw(
    setup_testenv
    silence_logg
    clear_log
    write_config_file
    write_dnsapi_stub
    $TMPDIR
    @LOG_LINES
);

use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(cwd);
use Data::Dumper;

our $TMPDIR;
our @LOG_LINES;

sub _default_config {
    return {
        acmesh_extra_params_install      => [],
        acmesh_extra_params_install_cert => [],
        acmesh_extra_params_issue        => [],
        email                            => 'test@example.com',
        dns_provider                     => 'dns_test',
        env                              => {},
        hostname                         => 'test.example.com',
        bind                             => '*:0',
        auth                             => [
            { user => 'bob',   pass => 'dobbs',  host => 'bob.example.com' },
            { user => 'alice', pass => 'rabbit', host => 'alice.example.com' },
        ],
    };
}

# Stub dnsapi provider. Both add/rm honour $ACMEPROXY_TEST_FAIL: if set, return 1.
# Each invocation appends a line to $HOME/.acme.sh/calls.log so tests can assert
# on call count and arguments.
my $DNSAPI_STUB = <<'EOSH';
dns_test_add() {
  echo "add $1 $2" >> "$HOME/.acme.sh/calls.log"
  [ -n "$ACMEPROXY_TEST_FAIL" ] && return 1
  return 0
}
dns_test_rm() {
  echo "rm $1 $2" >> "$HOME/.acme.sh/calls.log"
  [ -n "$ACMEPROXY_TEST_FAIL" ] && return 1
  return 0
}
EOSH

# Write a named dnsapi provider stub (e.g. dns_a) used by multi-provider tests.
# Each add/rm invocation appends a line to calls.log of the form:
#   <name> <action> <fqdn> <value> KEY1=<val> KEY2=<val> ...
# logging the live values of @env_keys so tests can assert which provider was
# selected AND which env vars were in scope for that call. Honours
# $ACMEPROXY_TEST_FAIL like the default dns_test stub.
sub write_dnsapi_stub {
    my ($name, @env_keys) = @_;
    my $envdump = join(' ', map { "$_=\$$_" } @env_keys);
    my $body = <<"EOSH";
${name}_add() {
  echo "$name add \$1 \$2 $envdump" >> "\$HOME/.acme.sh/calls.log"
  [ -n "\$ACMEPROXY_TEST_FAIL" ] && return 1
  return 0
}
${name}_rm() {
  echo "$name rm \$1 \$2 $envdump" >> "\$HOME/.acme.sh/calls.log"
  [ -n "\$ACMEPROXY_TEST_FAIL" ] && return 1
  return 0
}
EOSH
    _write_file("$TMPDIR/.acme.sh/dnsapi/$name.sh", $body);
}

sub _write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "can't write $path: $!";
    print $fh $content;
    close $fh;
}

sub write_config_file {
    my ($dir, $config) = @_;
    my $dumped = Data::Dumper->new([$config])->Terse(1)->Sortkeys(1)->Indent(1)->Dump;
    _write_file("$dir/acmeproxy.pl.conf", $dumped);
    chmod 0600, "$dir/acmeproxy.pl.conf";
}

sub setup_testenv {
    my %opts = @_;

    $TMPDIR = tempdir(CLEANUP => 1);
    $ENV{HOME} = $TMPDIR;

    make_path("$TMPDIR/.acme.sh/dnsapi");
    _write_file("$TMPDIR/.acme.sh/acme.sh", "# stub\n");

    unless (exists $opts{write_dnsapi} && !$opts{write_dnsapi}) {
        _write_file("$TMPDIR/.acme.sh/dnsapi/dns_test.sh", $DNSAPI_STUB);
    }

    _write_file("$TMPDIR/.acme.sh/acmeproxy.pl.crt", "");
    _write_file("$TMPDIR/.acme.sh/acmeproxy.pl.key", "");

    my $config = exists $opts{config} ? $opts{config} : _default_config();
    write_config_file($TMPDIR, $config);

    chdir $TMPDIR or die "can't chdir $TMPDIR: $!";

    return $TMPDIR;
}

sub silence_logg {
    no warnings 'redefine';
    *main::logg = sub { push @LOG_LINES, $_[0] };
}

sub clear_log {
    @LOG_LINES = ();
}

1;
