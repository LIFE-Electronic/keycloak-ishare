#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

case "${1:-}" in
  ""|--skip-build) ;;
  *) echo "Usage: $0 [--skip-build]" >&2; exit 1 ;;
esac

export JAVA_HOME="${JAVA_HOME:-$HOME/.sdkman/candidates/java/17.0.0-tem}"
if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
  echo "Set JAVA_HOME to your Java 17 installation." >&2
  exit 1
fi

if [[ "${1:-}" != --skip-build ]]; then
  ./mvnw -pl server-spi-private,services,quarkus/server -DskipTests install
fi

export KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
export KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

exec "$JAVA_HOME/bin/java" -jar quarkus/server/target/lib/quarkus-run.jar \
  start-dev --http-host=127.0.0.1 --http-port=8080
