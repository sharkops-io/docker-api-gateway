FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/docker-api-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/docker-api-gateway /docker-api-gateway
EXPOSE 9375
USER nonroot:nonroot
ENTRYPOINT ["/docker-api-gateway"]
