# acmeproxy.pl
Proxy server for ACME DNS-01 challenges, with native support in [acme.sh](https://github.com/acmesh-official/acme.sh), [Caddy](https://caddyserver.com), and [Traefik](https://traefik.io)

## tl;dr
- Possess a domain name hosted on a DNS provider supported by the acme.sh [dnsapi](https://github.com/acmesh-official/acme.sh/wiki/dnsapi)
- Configure your internal DNS to locally serve records such as pictures.int.example.com pointing at the internal IP of your services
- Set up acmeproxy.pl and give it access to your DNS provider's API.
- Use acme.sh, Caddy, or Traefik on internal hosts to request and maintain TLS certificates for *.int.example.com hostnames via acmeproxy

You now have TLS certificates for your internal services that have been signed by a trusted CA. https:// will Just Work from every device.

## Why?
Internal hosts need per-service TLS certificates, but giving every host direct DNS API credentials is a major security risk. acmeproxy.pl solves this by acting as an authenticated proxy. It centrally holds the sensitive DNS credentials and restricts access, ensuring users can only request certificates for their specifically authorized hostnames.

## Install
Install dependencies:
 - debian-ish: ```apt install libmojolicious-perl curl```
 - others: install curl and cpanminus. run ```cpanm Mojolicious```


Download acmeproxy.pl:
```bash
curl -O https://raw.githubusercontent.com/madcamel/acmeproxy.pl/master/acmeproxy.pl
chmod +x acmeproxy.pl
```

Run `./acmeproxy.pl` directly to generate `acmeproxy.pl.conf`. Edit it, then run `./acmeproxy.pl` again. For initial testing it's best to run it directly so you can see the output. If it generates its own TLS certificate you've configured the DNS provider correctly.

For normal use, acmeproxy.pl manages its own process and logs to `acmeproxy.log`:
```bash
./acmeproxy.pl start    # start in background
./acmeproxy.pl stop     # stop
./acmeproxy.pl reload   # restart (e.g. after editing config)
./acmeproxy.pl status   # check if running
./acmeproxy.pl check    # restart if dead; suitable for cron
```

To have it restart automatically if it dies, add a crontab entry:
```
*/5 * * * * /path/to/acmeproxy.pl check >/dev/null 2>&1
@reboot /path/to/acmeproxy.pl check >/dev/null 2>&1
```

Or just run it in tmux like some sort of heathen.

acmeproxy.pl does not require a restart when acme.sh renews its TLS certificate.

## Usage

### Using acme.sh with acmeproxy
Sample acme.sh usage:
```bash
ACMEPROXY_ENDPOINT="https://acmeproxy.int.example.com:9443" \
ACMEPROXY_USERNAME="bob" ACMEPROXY_PASSWORD="dobbs" \
acme.sh --log --issue dns dns_acmeproxy -d bob.int.example.com
```
You will then want to install the certificate with something like:
```bash
acme.sh --log --install-cert -d bob.int.example.com --key-file /etc/nginx/bob.key --fullchain-file /etc/nginx/bob.crt --reloadcmd "systemctl reload nginx.service"
```

See `acme.sh --help install-cert` for the full list of `--reloadcmd` and deploy-hook options.

Traefik supports acmeproxy via the ['httpreq'](https://doc.traefik.io/traefik/v3.3/https/acme/#providers) provider.
Caddy supports acmeproxy via the ['acmeproxy'](https://caddyserver.com/docs/json/admin/identity/issuers/acme/challenges/dns/provider/acmeproxy) provider

## Docker

**docker compose:**
```yaml
name: "acmeproxy"

services:
  acmeproxy:
    image: ghcr.io/madcamel/acmeproxy.pl
    restart: unless-stopped
    ports:
      - "9443:9443"
    volumes:
      - ./config:/config:rw
```

**docker CLI:**
```console
docker run -d \
  -p 9443:9443 \
  -v /path/to/config:/config:rw \
  --restart unless-stopped \
  ghcr.io/madcamel/acmeproxy.pl
```

If you're using a reverse proxy, replace `ports` with `expose` in compose (or drop `-p` from the CLI command).

### Persistent certificate storage

Without persistence, every container restart triggers a fresh ACME issuance. Let's Encrypt caps duplicate certificates at 5 per week. To persist certificate data, add a volume mount (`-v /path/to/cert-data:/cert-data:rw` or the compose equivalent) and add to `acmeproxy.pl.conf`:

```perl
acmesh_extra_params_install      => ['--config-home /cert-data'],
acmesh_extra_params_install_cert => ['--config-home /cert-data'],
acmesh_extra_params_issue        => ['--config-home /cert-data'],
keypair_directory                => '/cert-data',
```

## Security Notes
acmeproxy.pl was written to be run within an internal network. It's not recommended to expose your acmeproxy.pl host to the outside world.

Use of this certificate scheme will expose your internal network's hostnames via the certificate signer's public certificate transparency logs. If you're not comfortable with that, it is recommended not to use this approach. Please note that this is not a failing in acmeproxy.pl, but rather a characteristic of how public certificate authorities operate.

## Credits
A BIG thank you to [acmeproxy](https://github.com/mdbraber/acmeproxy/) for building almost exactly the tool I was looking for. Unfortunately it no longer works and is unmaintained.

