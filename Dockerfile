FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/docker-api-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/docker-api-gateway /docker-api-gateway
EXPOSE 9375
USER nonroot:nonroot
# Exec form, and the binary probing itself: this image is distroless, so there
# is no shell, curl or wget for a conventional healthcheck.
#
# This process does NOT inherit the flags the server was started with, so the
# probe detects http-vs-https itself. A non-default -addr is the one case that
# still needs this line overridden in compose alongside it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/docker-api-gateway", "-healthcheck"]
ENTRYPOINT ["/docker-api-gateway"]
