use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use AcmeProxyTest qw(setup_testenv);

setup_testenv();
require "$FindBin::Bin/../acmeproxy.pl";
AcmeProxyTest::silence_logg();

ok(defined &main::check_auth, 'check_auth defined in main::');
ok(defined &main::acme_cmd,   'acme_cmd defined in main::');
ok(main::app()->isa('Mojolicious'), 'app is a Mojolicious instance');

my @paths = sort map { $_->pattern->unparsed } @{main::app()->routes->children};
is_deeply(\@paths, [sort '/*', '/cleanup', '/present'], 'expected routes registered')
    or diag explain \@paths;

done_testing();
