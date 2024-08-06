FROM ubuntu

WORKDIR /config
VOLUME /config
ENV HOME="/config"
EXPOSE 9443

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y libmojolicious-perl curl \
    && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

COPY acmeproxy.pl /app/acmeproxy.pl

CMD [ "perl", "/app/acmeproxy.pl" ]
