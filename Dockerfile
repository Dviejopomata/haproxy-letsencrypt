FROM golang:1.10.3 as build-env

RUN curl -fsSL -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && chmod +x /usr/bin/dep

WORKDIR $GOPATH/src/github.com/Dviejopomata/haproxy-letsencrypt

COPY Gopkg.toml Gopkg.lock ./
COPY cmd ./cmd
COPY main.go ./
COPY vendor ./vendor
COPY pkg ./pkg
COPY log ./log
RUN go build -ldflags "-s -w"  -o "haproxy-le" main.go

FROM gcr.io/distroless/base
COPY --from=build-env /go/src/github.com/Dviejopomata/haproxy-letsencrypt/haproxy-le /
ENV GIN_MODE=release
ENTRYPOINT ["/haproxy-le"]
