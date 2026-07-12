#!/bin/sh
set -eu

instance_dir="${ONCEPROOF_INSTANCE_DIR:-/var/lib/onceproof/instance}"
default_config="$instance_dir/onceproof.toml"

if [ "$#" -eq 0 ]; then
    set -- serve
fi

if [ "$#" -eq 1 ] && [ "$1" = "serve" ]; then
    set -- serve --config "$default_config"
fi

if [ "$1" = "serve" ] && [ "${2:-}" = "--config" ] && [ "${3:-}" = "$default_config" ] && [ ! -f "$default_config" ]; then
    onceproof init "$instance_dir" \
        --host 0.0.0.0 \
        --port "${ONCEPROOF_PORT:-8787}" \
        --allow-public-bind
fi

exec onceproof "$@"
