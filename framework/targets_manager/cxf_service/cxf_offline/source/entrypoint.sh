#!/bin/sh
set -f
# shellcheck disable=SC2086
export CATALINA_OPTS="$JACOCO_OPTS $CATALINA_OPTS"
exec /usr/local/tomcat/bin/catalina.sh run
