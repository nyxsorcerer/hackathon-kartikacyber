#!/bin/sh
# Builds the On-server agent for linux/amd64 and linux/arm64 into $1 (default: dist),
# with SHA256SUMS. Downloads nothing; run it inside the digest-pinned golang image.
set -eu
cd "$(dirname "$0")"
out="${1:-dist}"
export CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly GOOS=linux
mkdir -p "$out"
for arch in amd64 arm64; do
	GOARCH=$arch go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$out/asset-monitor-agent-linux-$arch" .
done
cd "$out"
sha256sum asset-monitor-agent-linux-amd64 asset-monitor-agent-linux-arm64 >SHA256SUMS
cat SHA256SUMS
