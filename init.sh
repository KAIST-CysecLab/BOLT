#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
mkdir -p .cache

# docker-compose.yml mounts the host's Docker socket into the bolt container and adds
# the socket's group to the container user. Without a socket, Docker would mount an
# empty directory in its place and there would be no group to add, so stop here.
# BOLT_DOCKER_SOCK only exists so tests can point this check elsewhere.
DOCKER_SOCK="${BOLT_DOCKER_SOCK:-/var/run/docker.sock}"
if [ ! -S "$DOCKER_SOCK" ]; then
  cat >&2 <<EOT
[-] Error: no Docker socket at $DOCKER_SOCK.

    docker-compose.yml mounts /var/run/docker.sock into the bolt container. Start the
    Docker daemon, or make its socket available at that path (rootless Docker, for
    example, listens elsewhere), then run init.sh again.
EOT
  exit 1
fi
SOCK_GID="$(stat -c %g "$DOCKER_SOCK")"

env_get() {
  if [ -f .env ]; then
    sed -n "s/^$1=//p" .env | tail -n 1
  fi
}

random_secret() {
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

# MySQL applies its passwords only when it first initializes the mysql_data volume, so
# they are generated once and kept across runs: a new password would lock bolt out of
# an existing database.
MYSQL_PASSWORD="$(env_get MYSQL_PASSWORD)"
MYSQL_ROOT_PASSWORD="$(env_get MYSQL_ROOT_PASSWORD)"
new_credentials=false
if [ -z "$MYSQL_PASSWORD" ] || [ -z "$MYSQL_ROOT_PASSWORD" ]; then
  MYSQL_PASSWORD="$(random_secret)"
  MYSQL_ROOT_PASSWORD="$(random_secret)"
  new_credentials=true
fi

# A mysql_data volume left by an earlier install keeps that install's password, which
# the one just generated cannot open. Stop before writing .env, so that running this
# again after removing the volume still takes this path.
if [ "$new_credentials" = true ]; then
  project="$(MYSQL_PASSWORD=x MYSQL_ROOT_PASSWORD=x SOCK_GID=x docker compose config 2>/dev/null \
    | sed -n 's/^name: //p' | head -n 1)"
  volumes=""
  if [ -n "$project" ]; then
    volumes="$(docker volume ls -q \
      --filter "label=com.docker.compose.project=$project" \
      --filter label=com.docker.compose.volume=mysql_data)"
  fi
  if [ -n "$volumes" ]; then
    # Plain docker commands: compose itself refuses to run until .env holds the
    # passwords, which this run deliberately has not written yet.
    containers="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
    {
      echo "[-] Error: an existing MySQL volume was created with credentials that .env does not hold."
      echo
      echo "    MySQL applies its password only when it first creates the volume, so a new"
      echo "    password cannot open it. Remove the volume and run init.sh again; the"
      echo "    vulnerability database is downloaded again from the official Trivy DB:"
      echo
      if [ -n "$containers" ]; then
        echo "      docker rm -f" $containers
      fi
      echo "      docker volume rm" $volumes
      echo "      ./init.sh"
    } >&2
    exit 1
  fi
fi

cat > .env <<EOF
UID=$(id -u)
GID=$(id -g)
SOCK_GID=$SOCK_GID
MYSQL_PASSWORD=$MYSQL_PASSWORD
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD
EOF
chmod 600 .env

# Ghidra is mounted from this checkout at scan time, not baked into the image, so it is
# fetched here. The component database is not distributed; the script only warns when
# it is missing, and bin-sbom scans stop until it is built (see README.md).
if [ "${INSTALL_BIN_SBOM:-true}" = "true" ]; then
  ./fetch-bin-sbom-data.sh
fi

# This build bypasses docker-compose.yml, so the build args declared there do not
# apply. Forward INSTALL_BIN_SBOM explicitly, otherwise `--binary-sbom bin-sbom`
# has no way to reach the image.
docker build -f Dockerfile.bolt \
  --build-arg INSTALL_BIN_SBOM="${INSTALL_BIN_SBOM:-true}" \
  -t bolt:dev .
exec ./update-db.sh "$@"
