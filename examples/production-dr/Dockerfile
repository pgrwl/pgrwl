# PostgreSQL image with the pgrwl binary inside.
#
# The restore path needs `pgrwl` in the same container as PostgreSQL:
#   - `pgrwl restore` writes the base backup into PGDATA
#   - `restore_command = 'pgrwl restore-command ...'` fetches WAL during recovery
#
# The binary comes from the GitHub release for the container's architecture,
# so the image builds the same way on amd64 and arm64 hosts.
ARG PG_IMAGE=postgres:17.9-bookworm
FROM ${PG_IMAGE}

ARG PGRWL_VERSION=1.0.39
ARG TARGETARCH
ADD https://github.com/pgrwl/pgrwl/releases/download/v${PGRWL_VERSION}/pgrwl_v${PGRWL_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/pgrwl.tgz
RUN tar -xzf /tmp/pgrwl.tgz -C /usr/local/bin pgrwl && rm -f /tmp/pgrwl.tgz && pgrwl --version
