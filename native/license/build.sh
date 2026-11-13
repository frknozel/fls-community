#!/bin/sh
set -eu
: "${GO:=go}"
: "${OUT:=/tmp/fls-license-artifacts/fls-license-core}"
CHANNEL="${CHANNEL:-development}"
case "$CHANNEL" in development|commercial) ;; *) echo "Invalid CHANNEL" >&2; exit 64;; esac
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
export GOCACHE="${GOCACHE:-/tmp/fls-license-go-cache}"
cd "$(dirname "$0")"
"$GO" test ./... -count=1
mkdir -p "$(dirname "$OUT")"
"$GO" build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.buildChannel=$CHANNEL" -o "$OUT" .
"$OUT" version
sha256sum "$OUT"
