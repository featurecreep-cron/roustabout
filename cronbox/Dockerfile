FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server git \
    && rm -rf /var/lib/apt/lists/*

ARG DOCKER_GID=984
RUN groupadd -g ${DOCKER_GID} dockersock \
    && useradd -m -s /bin/bash -u 1000 -G dockersock cron

# sshd config and host keys in user-writable location — no root needed
RUN mkdir -p /etc/cronbox /run/sshd \
    && ssh-keygen -q -N "" -t ed25519 -f /etc/cronbox/ssh_host_ed25519_key \
    && chown -R cron:cron /etc/cronbox /run/sshd

COPY sshd_config /etc/cronbox/sshd_config

ARG AUTHORIZED_KEY
RUN mkdir -p /home/cron/.ssh \
    && echo "${AUTHORIZED_KEY}" > /home/cron/.ssh/authorized_keys \
    && chmod 700 /home/cron/.ssh \
    && chmod 600 /home/cron/.ssh/authorized_keys \
    && chown -R cron:cron /home/cron/.ssh

USER cron

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/cronbox/sshd_config"]
