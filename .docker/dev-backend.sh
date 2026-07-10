#!/bin/sh
set -eu

app_pid=""

cleanup() {
  if [ -n "${app_pid:-}" ] && kill -0 "$app_pid" 2>/dev/null; then
    kill "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
  fi
}

snapshot() {
  timeout 10s find pom.xml src/main/java src/main/resources templates \
      -type f \( -name '*.java' -o -name '*.properties' -o -name '*.xml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.ftl' \) \
      -printf '%T@ %p\n' 2>/dev/null \
    | sort \
    | sha256sum \
    | awk '{print $1}'
}

start_app() {
  jvm_arguments="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -Dspring.devtools.restart.enabled=false"
  mvn -DskipTests "-Dspring-boot.run.jvmArguments=${jvm_arguments}" spring-boot:run &
  app_pid=$!
}

restart_app() {
  cleanup
  start_app
}

trap cleanup INT TERM EXIT

mvn -q -DskipTests compile
start_app
last_snapshot="$(snapshot)"

while true; do
  sleep 2
  if ! kill -0 "$app_pid" 2>/dev/null; then
    echo "Backend process exited; restarting..."
    restart_app
    last_snapshot="$(snapshot)"
    continue
  fi

  current_snapshot="$(snapshot)"
  if [ "$current_snapshot" != "$last_snapshot" ]; then
    last_snapshot="$current_snapshot"
    echo "Detected backend change; recompiling and restarting..."
    if mvn -q -DskipTests compile; then
      restart_app
    else
      echo "Compile failed; keeping current backend process running."
    fi
  fi
done
