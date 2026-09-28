# Lab-only mail server: Postfix (SMTP) + Dovecot (IMAP/POP3).
# Never point this at a real network. Dummy credentials only. See CLAUDE.md.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix \
        dovecot-core \
        dovecot-imapd \
        dovecot-pop3d \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dummy lab user for AUTH testing. Never a real credential.
RUN useradd -m -s /usr/sbin/nologin labuser \
    && echo "labuser:labpass" | chpasswd

COPY postfix/main.cf /etc/postfix/main.cf
COPY postfix/master.cf /etc/postfix/master.cf
COPY dovecot/dovecot.conf /etc/dovecot/dovecot.conf
COPY dovecot/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf
COPY dovecot/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
COPY dovecot/10-master.conf /etc/dovecot/conf.d/10-master.conf
COPY dovecot/lab-users.txt /etc/dovecot/lab-users.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Certs are bind-mounted at runtime from lab/certs (never baked into the image).
EXPOSE 25 465 143 993 110 995

ENTRYPOINT ["/entrypoint.sh"]
