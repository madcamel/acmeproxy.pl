# acmeproxy.pl
Easy to install and use proxy server for ACME DNS challenges written in perl

Utilizes [acme.sh](https://github.com/acmesh-official/acme.sh) to solve ACME DNS challenges for hosts on an internal network.

## tl;dr
- Register a domain name hosted on a DNS provider supported by [acme.sh](https://github.com/acmesh-official/acme.sh)'s dnslib
- Configure your internal DNS to locally serve records such as pictures.int.mydomain.com pointing at the internal IPs of your services.
- Setup acmeproxy.pl and give it access to your DNS provider's API.
- Use acme.sh on internal hosts to request and maintain TLS certificates for *.int.mydomain.com hostnames via acmeproxy

Shebam! You now have real TLS certificates for your internal services that have been signed by a trusted CA. https:// will Just Work from every device. No need to run your own certificate authority and jump through hoops!

## Why?
acmeproxy.pl was written to make it easier and safer to automatically issue per-service [Let's Encrypt](https://letsencrypt.org) TLS certificates on an internal network.

There are three main ways to handle internal TLS certificates:
- Run a certificate authority. This is good for enterprises but probably overkill for smaller setups.

- Use something like certbot to generate certificates on a central host, then distribute the certificates to every host on the network. This can be error prone and difficult to orchestrate.
- Allow individual hosts to manage their own certificates by providing access to the DNS API for acme challenges. This is convenient but a massive security risk as every host will have unfettered access to the DNS API.


As a solution acmeproxy.pl provides the following:
- Allow internal hosts to request ACME DNS challenges through a single host, without individual / full API access to the DNS provider
- Provide a single (acmeproxy.pl) host that has access to the DNS credentials / API, limiting a possible attack surface
- Fine grained access control by tying usernames to allowed certificate hostnames
- Installs and manages its own TLS cetrificate via acme.sh

## Install
Install dependencies:
 - debian-ish: ```apt install libmojolicious-perl curl```
 - others: install curl and cpanminus. run ```cpanm Mojolicious```


Download acmeproxy.pl
```bash
curl -O https://raw.githubusercontent.com/madcamel/acmeproxy.pl/master/acmeproxy.pl; chmod +x acmeproxy.pl
```
run ./acmeproxy.pl to generate a the acmeproxy.pl.conf configuration file. 

Edit the configuration then run ./acmeproxy.pl again. If it is able to generate it's own TLS certificate you probably have configured the DNS provider correctly.

 To daemonize: 
 - use systemd
 - OR ```nohup ./acmeproxy.pl >>acmeproxy.log 2>&1 &```
 - OR ```hypnotoad acmeproxy.pl```
 - OR run it in tmux like some sort of heathen

## Docker

To use the tool with docker you have 2 options: docker CLI or docker compose.

For docker compose you can use the following file as a reference:
```yaml
# $schema: "https://raw.githubusercontent.com/compose-spec/compose-spec/master/schema/compose-spec.json"
name: "acmeproxy"

services:
  acmeproxy:
    image: ghcr.io/madcamel/acmeproxy.pl
    restart: unless-stopped
    port: # Or use expose when using a reverse proxy
      - 9443/tcp
    volumes:
      - ./config:/config:rw
```

Use the Docker CLI you can achive something similar using:
```console
docker run \
  -p 9443/tcp \
  -v /path/to/config:/config:rw \
  --restart unless-stopped \
  ghcr.io/madcamel/acmeproxy.pl
```

### Using acme.sh with acmeproxy
Sample acme.sh usage:
```bash
ACMEPROXY_ENDPOINT="https://acmeproxy.int.example.com:9443" \
ACMEPROXY_USERNAME="bob" ACMEPROXY_PASSWORD="dobbs" \
acme.sh --log --issue dns dns_acmeproxy -d bob.int.example.com
```
You will then want to install the certificate with something like:
```bash
acme.sh --log --install-cert -d $hn --key-file /etc/nginx/bob.key --fullchain-file /etc/nginx/bob.crt --reloadcmd "systemctl reload nginx.service"
```

This is not always the best way to do things. Please refer to the acme.sh documentation.

## Security Notes
acmeproxy.pl was written to be run within an internal network. It's not recommended to expose your acmeproxy.pl host to the outside world.

Use of this certificate scheme will expose your internal network's hostnames via the certificate signer's public certificate transparency logs. If you're not comfortable with that, it is recommended not to use this approach. Please note that this is not a failing in acmeproxy.pl, but rather a characteristic of how public certificate authorities operate.

## Credits
A BIG thank you to [acmeproxy](https://github.com/mdbraber/acmeproxy/) for building almost exactly the tool I was looking for. Unfortunately it no longer works and is unmaintained.

