# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -m 0700 /state
ARG TARGETOS=linux
ARG TARGETARCH

FROM build AS build-server
RUN mkdir -m 0755 /public
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/wanglou-server ./cmd/wanglou-server

FROM build AS build-agent
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/wanglou-agent ./cmd/wanglou-agent

FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build-server /out/wanglou-server /usr/local/bin/wanglou-server
COPY --from=build-server --chown=65532:65532 /state /data
COPY --from=build-server --chown=65532:65532 /public /public
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wanglou-server"]
CMD ["serve"]

FROM gcr.io/distroless/static-debian12:nonroot AS agent
COPY --from=build-agent /out/wanglou-agent /usr/local/bin/wanglou-agent
COPY --from=build-agent --chown=65532:65532 /state /var/lib/wanglou
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wanglou-agent"]
CMD ["run", "--config", "/var/lib/wanglou/agent.toml"]
