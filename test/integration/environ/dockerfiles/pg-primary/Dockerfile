FROM debian:bookworm-20251117-slim

# Version argument
ARG PG_MAJOR=17
ENV PG_MAJOR=${PG_MAJOR}
RUN echo "export PG_MAJOR=${PG_MAJOR}" > /etc/profile.d/pgenvs.sh; \
    echo "export PG_MAJOR=${PG_MAJOR}" >> /etc/environment; \
    echo "export PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}" > /etc/profile.d/utils.sh;
# Envs
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Aqtau
ENV PATH="/usr/lib/postgresql/${PG_MAJOR}/bin:${PATH}"

RUN touch /etc/apt/apt.conf.d/99verify-peer.conf \
    && echo >>/etc/apt/apt.conf.d/99verify-peer.conf "Acquire { https::Verify-Peer false }"

######################################################################
# Install PostgreSQL and other utilities

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -eux; \
    # packages
    apt-get update; \
    apt-get install -y --no-install-recommends \
      curl gnupg lsb-release ca-certificates \
      openssh-server sudo vim net-tools telnet mc python3 strace \
      postgresql-common tzdata; \
    # pg
    YES=true /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      postgresql-${PG_MAJOR} postgresql-client-${PG_MAJOR}; \
    # tz
    echo $TZ > /etc/timezone; \
    ln -sf /usr/share/zoneinfo/$TZ /etc/localtime; \
    dpkg-reconfigure -f noninteractive tzdata; \
    # ssh
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config; \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config; \
    # afterall
    mkdir /var/run/sshd; \
    rm -rf "/var/lib/postgresql/${PG_MAJOR}" && mkdir -p "/var/lib/postgresql/${PG_MAJOR}/main/pgdata";

######################################################################
# Copy files, configs

COPY files/postgres/ /etc/postgresql/${PG_MAJOR}/main
COPY files/dotfiles/ /var/lib/postgresql
COPY files/dotfiles/ /root
COPY files/entrypoint.sh /entrypoint.sh

######################################################################
# Setup users

RUN echo "postgres:postgres" | chpasswd; \
    echo "postgres ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/postgres; \
    mkdir -p /var/lib/postgresql/.ssh;  \
    chmod 700 /var/lib/postgresql/.ssh; \
    chmod 600 /var/lib/postgresql/.ssh/authorized_keys; \
    chmod 600 /var/lib/postgresql/.ssh/id_ed25519; \
    chown -R postgres:postgres /var/lib/postgresql; \
    chown -R postgres:postgres /etc/postgresql; \
    chown -R postgres:postgres /var/log/postgresql; \
    # root user
    echo "root:root" | chpasswd; \
    mkdir -p /root/.ssh; \
    chmod 700 /root/.ssh; \
    # init
    chmod +x /entrypoint.sh

######################################################################
# Copy binaries (1)
COPY --from=quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z /usr/bin/mc /usr/local/bin/minio-mc

######################################################################
# Copy test scripts (these files are frequently changed, so it's better to make this layer as late as possible)

COPY files/configs /var/lib/postgresql/configs
COPY scripts /var/lib/postgresql/scripts
RUN find /var/lib/postgresql/scripts/tests -type f -name '*.sh' -exec chmod +x {} \;
RUN chown -R postgres:postgres /var/lib/postgresql

######################################################################
# Copy binaries (2)
COPY bin/ /usr/local/bin

######################################################################
# Run container

EXPOSE 5432 22
ENTRYPOINT ["/entrypoint.sh"]
