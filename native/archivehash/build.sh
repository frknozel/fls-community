#!/bin/sh
set -eu
: "${GO:=go}"
: "${OUT:=/tmp/fls-archive-artifacts/fls-archive-hash}"
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
export GOCACHE="${GOCACHE:-/tmp/fls-archive-go-cache}"
cd "$(dirname "$0")"
"$GO" test -count=1 ./...
mkdir -p "$(dirname "$OUT")"
"$GO" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUT" .
sha256sum "$OUT"
