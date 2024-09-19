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

my $has_bcrypt = eval {
	require Crypt::Bcrypt;
	Crypt::Bcrypt->import();
	1;
};

die("$0: please install curl.\n") unless (-x `/usr/bin/which curl` =~ s/[\r\n]//r);

# acme.sh uses this log format so we're sort of stuck with it
sub logg ($in) { say strftime("[%a %b %e %I:%M:%S %p %Z %Y] ", localtime()) . $in };

write_config() unless (-f 'acmeproxy.pl.conf');
logg('WARNING: acmeproxy.pl.conf is world-readable. Please chmod 0600 acmeproxy.pl.conf') if ((stat('acmeproxy.pl.conf'))[2] & 04);
my $config = plugin 'Config' => {file => cwd().'/acmeproxy.pl.conf', format => 'perl'};

# Backwards compatibility checks/updates
if (!exists($config->{acmesh_extra_params_install})) {
  $config->{acmesh_extra_params_install} = [];
}
if (!exists($config->{acmesh_extra_params_install_cert})) {
  $config->{acmesh_extra_params_install_cert} = [];
}
if (!exists($config->{acmesh_extra_params_issue})) {
  $config->{acmesh_extra_params_issue} = [];
}
if ($has_bcrypt) {
  foreach my $auth (@{$config->{auth}}) {
    if (exists($auth->{pass})) {
      logg "One or more users are defined with plaintext passwords. You should convert them to bcrypt hashes!";
      last;
    }
  }
} else {
  foreach my $auth (@{$config->{auth}}) {
    if (exists($auth->{hash})) {
      die("One or more users are defined with bcrypt hashes, but Crypt::Bcrypt is not available. Either install Crypt::Bcrypt, or change these users to have a plaintext password!");
    }
  }
}
if (!exists($config->{keypair_directory})) {
  $config->{keypair_directory} = $acme_home;
}

# Set environment variables from config
foreach (keys %{$config->{env}}) { $ENV{$_} = $config->{env}->{$_}; }

# Install acme.sh if it isn't installed already
acme_install() unless (-f "$acme_home/acme.sh");

# Early sanity checks
die("acme dnslib provider not found: $config->{dns_provider}\n")
  unless (-f "$acme_home/dnsapi/$config->{dns_provider}.sh");

# Generate a TLS certificate for ourselves if one doesn't exist
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

  $c->render(text => acme_cmd($command, $data->{fqdn}, $data->{value}));
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
{
  my $watcher;
  my $cert_mtime = (stat("$acmeproxy_crt_file"))[9]; 
  $watcher = Mojo::IOLoop->recurring(1 => sub {
    if ((stat($acmeproxy_crt_file))[9] != $cert_mtime) {
      $cert_mtime = (stat($acmeproxy_crt_file))[9];
      logg "$acmeproxy_crt_file modified. Reloading";
      exec($^X, $0, @ARGV) or logg "reload failed!"; # Just re-exec ourselves
    }
  });
}

# Anchors aweigh!
app->start('daemon', '-m', 'production', '-l', "https://$config->{bind}?cert=$acmeproxy_crt_file&key=$acmeproxy_key_file");

# Add or remove a DNS record using the configured acme.sh DNS provider
# Hijacks acme.sh to use it's dnsapi library.
# Crude but effective. Slimy yet satisfying.
sub acme_cmd ($action, $fqdn, $value) {
  # Let's not pass weird characters to a shell
  return "invalid characters in fqdn" unless ($fqdn =~ /^[\w_\.-]+$/);
  return "invalid characters in value" unless ($value =~ /^[\w_\.-]+$/);
  $fqdn =~ s/\.+$//; # Some acme.sh plugins add an additional . to the end of the hostname

  my $shellcmd = '/usr/bin/env bash -c "' .
    "source $acme_home/acme.sh >/dev/null 2>&1; " .     		                  # Load all bash functions from acme.sh
    "source $acme_home/dnsapi/$config->{dns_provider}.sh; " .			            # source ~/.acme.sh/dns_cf.sh
    $config->{dns_provider}.'_'.$action.' \"'.$fqdn.'\" '.'\"'.$value.'\";"';	# dns_cf_add "sub.domain.com" "value123456"
  logg "executing: $shellcmd";

  # acme.sh/dnslib/dns_acmeproxy.sh explicitly looks for the quotes around $value to determine success
  return "success: $fqdn \"$value\"" unless (system("$shellcmd"));
  return "failed. check acmeproxy.pl logs";
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
    my $auth_check = 0;
    if (secure_compare($user, $auth->{user}) && $fqdn =~ /\.$auth->{host}\.?$/) {
      if ($has_bcrypt && exists($auth->{hash})) {
        $auth_check = Crypt::Bcrypt::bcrypt_check($pass, $auth->{hash});
      } else {
        $auth_check = secure_compare($pass, $auth->{pass});
      }
      if ($auth_check) {
        logg "auth: $user successfully authenticated for $fqdn";
        return 1;
      }
    }
  }
 
  logg "auth: Invalid credentials for user $user";
  return;
}

# Install acme.sh
sub acme_install {
  say "Installing acme.sh";
  my $extra_params_install = join(' ', @{$config->{acmesh_extra_params_install}});
  system("curl https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s -- --install-online -m $config->{email} $extra_params_install") && die("ouldn't install acme.sh\n");
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
