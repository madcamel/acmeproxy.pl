# acmeproxy.pl
Easy to install and use proxy server for ACME DNS challenges written in perl

Utilizes [acme.sh](https://github.com/acmesh-official/acme.sh) to solve ACME DNS challenges for hosts on an internal network.

## tl;dr
- Possess a domain name hosted on a DNS provider supported by the acme.sh [dnsapi](https://github.com/acmesh-official/acme.sh/wiki/dnsapi)
- Configure your internal DNS to locally serve records such as pictures.int.example.com pointing at the internal IP of your services
- Setup acmeproxy.pl and give it access to your DNS provider's API.
- Use acme.sh on internal hosts to request and maintain TLS certificates for *.int.example.com hostnames via acmeproxy

Shebam! You now have TLS certificates for your internal services that have been signed by a trusted CA. https:// will Just Work from every device.

## Why?
acmeproxy.pl was written to make it easier and safer to automatically issue per-service [Let's Encrypt](https://letsencrypt.org) or [ZeroSSL](https://zerossl.com/) TLS certificates on an internal network.

There are three main ways to handle internal TLS certificates:
- Run a certificate authority. This is good for enterprises but probably overkill for smaller setups.

- Use something like certbot to generate certificates on a central host, then distribute the certificates to every host on the network. This can be error prone and difficult to orchestrate.

- Allow individual hosts to manage their own certificates by providing access to the DNS API for acme challenges. This is convenient but a massive security risk as every host will have unfettered access to the DNS API.


As a fourth solution acmeproxy.pl provides the following:
- Allow internal non internet-exposed hosts to easily request TLS certificates using acme.sh
- Only the acmeproxy.pl service requires access to the DNS credentials, not all hosts
- Fine grained access control by tying credentials to allowed certificate hostnames
- Centralized service for logging and audit purposes
- Installs and manages its own TLS cetrificate via acme.sh
- Easy to use, few dependencies

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
      # Optionally store the generated certificate data on a persistent volume
      # - ./cert-data:/cert-data:rw
```

Note that if you want to store the generated certificate data on a persistant volume, you should add something like the following to your `acmeproxy.pl.conf` file:
```perl
# Extra params to pass when invoking acme.sh --install
acmesh_extra_params_install => [
    '--config-home /cert-data',
],

# Extra params to pass when invoking acme.sh --install-cert
acmesh_extra_params_install_cert => [
    '--config-home /cert-data',
],

# Extra params to pass when invoking acme.sh --issue
acmesh_extra_params_issue => [
    '--config-home /cert-data',
],

# The directory to store acmeproxy.pl.crt and acmeproxy.pl.key
keypair_directory => '/cert-data',
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
acme.sh --log --install-cert -d bob.int.example.com --key-file /etc/nginx/bob.key --fullchain-file /etc/nginx/bob.crt --reloadcmd "systemctl reload nginx.service"
```

This is not always the best way to do things. Please refer to the acme.sh documentation.

## Security Notes
acmeproxy.pl was written to be run within an internal network. It's not recommended to expose your acmeproxy.pl host to the outside world.

Use of this certificate scheme will expose your internal network's hostnames via the certificate signer's public certificate transparency logs. If you're not comfortable with that, it is recommended not to use this approach. Please note that this is not a failing in acmeproxy.pl, but rather a characteristic of how public certificate authorities operate.

## Credits
A BIG thank you to [acmeproxy](https://github.com/mdbraber/acmeproxy/) for building almost exactly the tool I was looking for. Unfortunately it no longer works and is unmaintained.

