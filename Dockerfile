FROM ubuntu

WORKDIR /config
VOLUME /config
ENV HOME="/config"
EXPOSE 9443

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cron libmojolicious-perl curl \
    && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

RUN curl -sSL https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz -o /tmp/s6-overlay-noarch.tar.xz
    && tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz
    && curl -sSL https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp/s6-overlay-x86_64.tar.xz
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz
    && rm /tmp/s6-overlay-noarch.tar.xz /tmp/s6-overlay-x86_64.tar.xz

COPY ./services.d /etc/services.d

ENTRYPOINT ["/init"]

COPY acmeproxy.pl /app/acmeproxy.pl

CMD [ "perl", "/app/acmeproxy.pl" ]
