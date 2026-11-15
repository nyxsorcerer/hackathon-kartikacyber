# Builds both agent binaries and SHA256SUMS; nothing is downloaded during the build.
# Export with: docker build --target agent-dist --output type=local,dest=agent/dist agent/
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS agent-build
WORKDIR /src
COPY go.mod build.sh ./
COPY *.go ./
RUN ./build.sh /out

FROM scratch AS agent-dist
COPY --from=agent-build /out/ /
