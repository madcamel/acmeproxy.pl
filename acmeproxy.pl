#!/usr/bin/env perl
# A simple acmeproxy server that's designed to be extremely easy to install and use
# This proxy supports every DNS provider available in acme.sh
#
# To install dependencies:
#   debian-ish: apt install libmojolicious-perl curl
#   others: install curl and cpanminus. run 'cpanm Mojolicious'
#
# To configure: run ./acmeproxy.pl to generate an example acmeproxy.pl.conf file
# Edit acmeproxy.pl.conf and run ./acmeproxy.pl again
#
# To daemonize: nohup ./acmeproxy.pl >>acmeproxy.log 2>&1 &
# OR hypnotoad acmeproxy.pl
#
# Note that one of the first things acmeproxy.pl will do is install acme.sh
# and procure a TLS certificate for itself using the configured DNS provider.
# The certificate will be stored in ~/.acme.sh/acmeproxy.pl.crt and .key
# and should be updated automatically by the acme.sh cron job.
#
# WARNING: This exposes your internal network hostnames to public certificate
# transparency logs. That's just how it is with Let's Encrypt/ZeroSSL/etc.
# If you're not comfortable with that, don't use this.
#
# Sample acme.sh usage:
# ACMEPROXY_ENDPOINT="https://acmeproxy.int.example.com:9443" \
# ACMEPROXY_USERNAME="bob" ACMEPROXY_PASSWORD="dobbs" \
# acme.sh --issue dns dns_acmeproxy -d bob.int.example.com


# Only change this if you are Gandalf
my $acme_home = "$ENV{'HOME'}/.acme.sh";

use Mojolicious::Lite -signatures;
use Mojo::Util qw(secure_compare);
use POSIX qw(strftime);
use Cwd;
use strict;

my $pidfile = cwd().'/acmeproxy.pid';
my $logfile  = cwd().'/acmeproxy.log';

if (@ARGV) {
  my $cmd = $ARGV[0];
  if ($cmd eq 'stop') {
    do_stop(); exit;
  } elsif ($cmd eq 'status') {
    my $pid = is_running();
    say $pid ? "running (pid $pid)" : "not running"; exit;
  } elsif ($cmd eq 'check') {
    exit 0 if is_running();
    print "not running, restarting\n";
    unlink $pidfile;
    exec($^X, $0, 'start') or die "exec failed: $!";
  } elsif ($cmd eq 'reload') {
    do_stop(); sleep 1;
    exec($^X, $0, 'start') or die "exec failed: $!";
  } elsif ($cmd eq 'start') {
    if (my $pid = is_running()) {
      print "already running (pid $pid)\n"; exit 1;
    }
    shift @ARGV;
    my $child = fork() // die "fork: $!";
    if ($child) {
      open(my $pf, '>', $pidfile) or die "pidfile: $!";
      print $pf $child; close $pf;
      print "started (pid $child)\n";
      exit 0;
    }
    POSIX::setsid();
    open(STDOUT, '>>', $logfile) or die;
    open(STDERR, '>&STDOUT')     or die;
  }
}

my $has_bcrypt = eval { require Crypt::Bcrypt; 1 };

chomp(my $curl_path = qx{command -v curl 2>/dev/null});
die("$0: please install curl.\n") unless -x $curl_path;

# acme.sh uses this log format so we're sort of stuck with it
sub logg ($in) { say strftime("[%a %b %e %I:%M:%S %p %Z %Y] ", localtime()) . $in };

write_config() unless (-f 'acmeproxy.pl.conf');
logg('WARNING: acmeproxy.pl.conf is world-readable. Please chmod 0600 acmeproxy.pl.conf') if ((stat('acmeproxy.pl.conf'))[2] & 04);
my $config = plugin 'Config' => {file => cwd().'/acmeproxy.pl.conf', format => 'perl'};

# Backwards compatibility defaults
$config->{acmesh_extra_params_install}      = [] unless exists $config->{acmesh_extra_params_install};
$config->{acmesh_extra_params_install_cert} = [] unless exists $config->{acmesh_extra_params_install_cert};
$config->{acmesh_extra_params_issue}        = [] unless exists $config->{acmesh_extra_params_issue};
$config->{keypair_directory}                = $acme_home unless exists $config->{keypair_directory};

# Validate auth entries against bcrypt availability
my ($has_plaintext, $has_hash) = (0, 0);
foreach my $auth (@{$config->{auth}}) {
  $has_plaintext ||= exists $auth->{pass};
  $has_hash      ||= exists $auth->{hash};
}
die("One or more users are defined with bcrypt hashes, but Crypt::Bcrypt is not available. Either install Crypt::Bcrypt, or change these users to have a plaintext password!\n")
  if ($has_hash && !$has_bcrypt);
logg "One or more users are defined with plaintext passwords. You should convert them to bcrypt hashes!"
  if ($has_plaintext && $has_bcrypt);

# Set environment variables from config (legacy single-provider mode)
unless (exists $config->{providers}) {
  foreach (keys %{$config->{env}}) {
    $ENV{$_} = $config->{env}->{$_};
  }
}

# Returns true if fqdn belongs to domain suffix
sub fqdn_matches_domain ($fqdn, $domain) {
  $fqdn =~ s/\.+$//;
  $domain =~ s/\.+$//;

  return 1 if ($fqdn eq $domain);
  return $fqdn =~ /\.\Q$domain\E$/;
}

# Find matching provider config for fqdn
sub get_provider_config_for_fqdn ($fqdn) {
  $fqdn =~ s/\.+$//;

  # Legacy single-provider mode
  unless (exists $config->{providers}) {
    return {
      dns_provider => $config->{dns_provider},
      env => $config->{env},
    };
  }

  foreach my $provider (@{$config->{providers}}) {
    foreach my $domain (@{$provider->{domains}}) {
      return $provider
        if fqdn_matches_domain($fqdn, $domain);
    }
  }

  die("No provider configured for domain: $fqdn\n");
}


# Install acme.sh if it isn't installed already
acme_install() unless (-f "$acme_home/acme.sh");

# Early sanity checks
if (exists $config->{providers}) {
  foreach my $provider (@{$config->{providers}}) {
    die("provider entry missing dns_provider\n")
      unless exists $provider->{dns_provider};

    die("provider entry missing domains\n")
      unless exists $provider->{domains};

    die("provider entry missing env\n")
      unless exists $provider->{env};

    die("acme dnslib provider not found: $provider->{dns_provider}\n")
      unless (-f "$acme_home/dnsapi/$provider->{dns_provider}.sh");
  }
} else {
  die("acme dnslib provider not found: $config->{dns_provider}\n")
    unless (-f "$acme_home/dnsapi/$config->{dns_provider}.sh");
}

# Generate a TLS certificate for ourselves if one doesn't exist
# Self-certificate always uses legacy global dns_provider/env config
# even in multi-provider mode.
my $acmeproxy_crt_file = "$config->{keypair_directory}/acmeproxy.pl.crt";
my $acmeproxy_key_file = "$config->{keypair_directory}/acmeproxy.pl.key";
acme_gencert($config->{hostname})
  unless (-f "$acmeproxy_key_file" && -f "$acmeproxy_crt_file");

# common handler for /present and /cleanup web routes
sub handle_request {
  my ($c, $command) = @_;
  $c->res->headers->www_authenticate('Basic');
  my $data = $c->req->json or return $c->render(text => 'Invalid JSON', status => 400);

  return $c->render(text => 'Invalid credentials', status => 401)
    unless check_auth($c->req->url->to_abs->userinfo, $data->{fqdn});

  # Remove the DNS record before adding it
  # This is to prevent acme.sh from failing if the record already exists
  # It really should be handled in acme.sh dnssapi/acme_proxy.sh but it's not
  acme_cmd("rm", $data->{fqdn}, $data->{value}) if ($command eq 'add');

  my $cmd_res = acme_cmd($command, $data->{fqdn}, $data->{value});

  my $accept = $c->req->headers->accept;
  if (defined $accept && $accept eq 'application/json') {
    $c->render(json => $cmd_res->{json}, status => $cmd_res->{status});
  } else {
    $c->render(text => $cmd_res->{text}, status => $cmd_res->{status});
  }
}

# Mojo web routes
post '/present' => sub ($c) { handle_request($c, 'add') };
post '/cleanup' => sub ($c) { handle_request($c, 'rm') };

# A silly default route to handle other requests
any '/*' => sub ($c) { $c->render(text => 'I am not a teapot. Please leave me alone.'); };

# Log all HTTP requests
hook before_dispatch => sub ($c) {
    logg join(' ', 'HTTP:', $c->tx->remote_address, $c->req->method, $c->req->url->to_abs);
};

# We used acme.sh to generate our TLS certificate so its cron job should update our cert regularly
# Check the TLS certificate file for changes every second and reload our app if it's been modified
my $cert_mtime = (stat($acmeproxy_crt_file))[9];
Mojo::IOLoop->recurring(1 => sub {
  my $mtime = (stat($acmeproxy_crt_file))[9];
  return if $mtime == $cert_mtime;
  $cert_mtime = $mtime;
  logg "$acmeproxy_crt_file modified. Reloading";
  exec($^X, $0, @ARGV) or logg "reload failed!"; # Just re-exec ourselves
});

# Anchors aweigh!
app->mode('production');
app->start('daemon', '-l', "https://$config->{bind}?cert=$acmeproxy_crt_file&key=$acmeproxy_key_file")
  unless caller;

# Add or remove a DNS record using the configured acme.sh DNS provider
# Hijacks acme.sh to use it's dnsapi library.
# Crude but effective. Slimy yet satisfying.
sub acme_cmd ($action, $fqdn, $value) {
  # Let's not pass weird characters to a shell
  return { status => 400, text => "invalid characters in fqdn",
           json => { error => "invalid characters in fqdn" } }
    unless ($fqdn =~ /^[\w_\.-]+$/);
  return { status => 400, text => "invalid characters in value",
           json => { error => "invalid characters in value" } }
    unless ($value =~ /^[\w_\.-]+$/);
  my $fqdn_unsanitized = $fqdn;
  $fqdn =~ s/\.+$//; # Some acme.sh plugins add an additional . to the end of the hostname

  my $provider_cfg;

  eval {
    $provider_cfg = get_provider_config_for_fqdn($fqdn);
  };

  if ($@) {
    logg "provider selection failed for $fqdn: $@";

    return {
      status => 500,
      text => "provider selection failed",
      json => { error => "provider selection failed" },
    };
  }

  my $dns_provider = $provider_cfg->{dns_provider};

  # Source acme.sh and the dnsapi provider, then call the provider's add/rm function.
  # fqdn and value are passed as positional args ($1, $2) rather than interpolated into
  # the shell string, so they can never be parsed as shell syntax.
  my $func = $dns_provider.'_'.$action;
  my $script = "source $acme_home/acme.sh >/dev/null 2>&1; " .
               "source $acme_home/dnsapi/$dns_provider.sh; " .
               '"$0" "$1" "$2"';
  logg "executing: $func \"$fqdn\" \"$value\"";

  local %ENV = %ENV;

  foreach (keys %{$provider_cfg->{env}}) {
    $ENV{$_} = $provider_cfg->{env}->{$_};
  }

  return {
    status => 200,
    text   => qq/success: $fqdn "$value"/,
    json   => { fqdn => $fqdn_unsanitized, value => $value },
  } unless (system('/usr/bin/env', 'bash', '-c', $script, $func, $fqdn, $value));
  return { status => 500, text => "failed. check acmeproxy.pl logs",
           json => { error => "failed. check acmeproxy.pl logs" } };
}

# Authentication helper. Checks user:pass and fqdn against our authlist
sub check_auth ($userpass, $fqdn) {
  unless ($userpass) {
    logg "credentials not supplied";
    return;
  }

  # $userpass is in the rather odd format of "username:password". Don't look at me, it's Mojolicious.
  my ($user, $pass) = split(/:/, $userpass, 2);

  foreach my $auth (@{$config->{auth}}) {
    next unless secure_compare($user, $auth->{user}) && $fqdn =~ /\.$auth->{host}\.?$/;

    my $ok = ($has_bcrypt && exists $auth->{hash})
      ? Crypt::Bcrypt::bcrypt_check($pass, $auth->{hash})
      : secure_compare($pass, $auth->{pass});

    if ($ok) {
      logg "auth: $user successfully authenticated for $fqdn";
      return 1;
    }
  }
 
  logg "auth: Invalid credentials for user $user";
  return;
}

# Install acme.sh
sub acme_install {
  say "Installing acme.sh";
  my $extra_params_install = join(' ', @{$config->{acmesh_extra_params_install}});
  system("curl https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s -- --install-online -m $config->{email} $extra_params_install") && die("Couldn't install acme.sh\n");
  say "Completed";
}

# Use acme.sh to generate and install a certificate for ourself if one doesn't exist
sub acme_gencert ($hn) {
  logg "Generating and installing TLS certificate for $hn";

  my $domain_list = join(' ', map { qq/-d ${_}/} split(/\s+/, $hn));
  my $extra_params_issue = join(' ', @{$config->{acmesh_extra_params_issue}});
  my $ret = system("$acme_home/acme.sh --log --issue $extra_params_issue " .
                   "--dns $config->{dns_provider} $domain_list");
  # --issue will return 2 when renewal is skipped due to certs still being valid
  die("Could not create TLS certificate for $hn") if ($ret != 0 && $ret >> 8 != 2);

  my $extra_params_install_cert = join(' ', @{$config->{acmesh_extra_params_install_cert}});
  $ret = system("$acme_home/acme.sh --log --install-cert $extra_params_install_cert $domain_list " .
                "--key-file $acmeproxy_key_file --fullchain-file $acmeproxy_crt_file");
  die("Could not install TLS certificate for $hn") if ($ret);
}

sub is_running {
  return 0 unless -f $pidfile;
  open(my $fh, '<', $pidfile) or return 0;
  chomp(my $pid = <$fh>); close $fh;
  return ($pid && kill(0, $pid)) ? $pid : 0;
}

sub do_stop {
  my $pid = is_running() or do { print "not running\n"; return; };
  kill('TERM', $pid) and unlink($pidfile) and print "stopped\n";
}

# Write the example configuration file
sub write_config() {
  open(my $fh, '>', 'acmeproxy.pl.conf') or die $!;
  print $fh $_ while <DATA>;
  close $fh;
  chmod(0600, 'acmeproxy.pl.conf');
  die("Example configuration file written. Please edit acmeproxy.pl.conf and restart\n");
}

# Include our own example configuration file because perl is awesome
__DATA__
{
    # acmeproxy.pl example configuration
    # This configuration file is in perl format.
    # It is unfortunate that perl JSON does not support comments

    # Extra params to be passed to acme.sh --install
    acmesh_extra_params_install => [],

    # Extra params to be passed to acme.sh --install-cert
    acmesh_extra_params_install_cert => [],

    # Extra params to be passed to acme.sh --issue
    acmesh_extra_params_issue => [
        '--server zerossl',
    ],

    # The directory in which to store acmeproxy.pl.crt and acmeproxy.pl.key
    # If this is left unspecified, it defaults to: "$ENV{'HOME'}/.acme.sh"
    #keypair_directory => '',

    # Email address for acme.sh certificate issuance and expiration notification
    # Required for Let's Encrypt and ZeroSSL
    email => 'example@example.com',

    # Which acme.sh DNS provider do we use?
    # See https://github.com/acmesh-official/acme.sh/wiki/dnsapi
    #dns_provider => 'dns_cf',
    dns_provider => 'please_edit_your_configfile',
    
    # Environment variables for the above acme.sh DNS provider
    env => {
        'CF_Token' => 'TWFkZXlhbG9vawo='
    },

    # Multi-provider / multi-account mode
    #
    # If providers => [...] is specified,
    # runtime ACME challenge requests will automatically
    # select the correct provider based on fqdn suffix.
    #
    # The first matching domain suffix wins.
    #
    # IMPORTANT:
    # Self-certificate generation for acmeproxy.pl itself
    # still uses the global dns_provider/env config above.
    #
    #providers => [
    #    {
    #        name => 'cloudflare-main',
    #
    #        dns_provider => 'dns_cf',
    #
    #        domains => [
    #            'example.org',
    #            'example.net',
    #        ],
    #
    #        env => {
    #            'CF_Token' => 'token1',
    #        },
    #    },
    #
    #    {
    #        name => 'route53-prod',
    #
    #        dns_provider => 'dns_aws',
    #
    #        domains => [
    #            'corp.internal',
    #        ],
    #
    #        env => {
    #            'AWS_ACCESS_KEY_ID' => 'xxx',
    #            'AWS_SECRET_ACCESS_KEY' => 'yyy',
    #        },
    #    },
    #],
        
    # This is the 'common' hostname of the machine where acmeproxy.pl is running.
    # acmeproxy.pl will generate a TLS certificate for this hostname.
    # acme.sh clients will then access acmeproxy.pl using this hostname
    # via https://<hostname>
    # Note that you can specify multiple hostnames if they're separated by spaces.
    hostname => 'acmeproxy.int.example.com',
    
    # Hostname and port to listen on. * means all ipv4/ipv6 addresses
    bind => '*:9443',
    
    # Authentication list. This contains the ACMEPROXY_USER/ACMEPROXY_PASS pairs
    # required to access acmeproxy.pl. Each user record is associated with a
    # specific authorized hostname. Subdomains of this hostname are also allowed.
    #
    # Passwords stored in this file can either be in plain text, or hashed with bcrypt.
    # If you chose to use bcrypted passwords, you must have the Crypt::Bcrypt module
    # installed. If Crypt::Bcrypt is installed but some users are using plain text
    # passwords, a warning will be printed on startup. You can safely ignore this if
    # you like.
    #
    # If a user has a plain text password as well as a hashed password, and the
    # Crypt::Bcrypt module is installed, ONLY the hashed password will be checked!
    'auth' => [
        # Allow bob (password dobbs) to generate certificates for bob.int.example.com
        # bob can also use these credentials to generate certificates for subdomains
        # like slackbox.bob.int.example.com
        {
            'user' => 'bob',
            'pass' => 'dobbs',
            # 'hash' => '$2b$12$ZkfzP1DVcFHSXyrtMRXJR.Ny2fpSixG00oLI2iMkT3yArpzs/921u',
            'host' => 'bob.int.example.com',
        },
        # Bob is hosting two TLS services on his machine with different TLS hostnames
        # Allow his credentials to generate certificates for the additional hostname as well
        {
            'user' => 'bob',
            'pass' => 'dobbs',
            # 'hash' => '$2b$12$ZkfzP1DVcFHSXyrtMRXJR.Ny2fpSixG00oLI2iMkT3yArpzs/921u',
            'host' => 'subgenius.int.example.com',
        },
    ],
}
