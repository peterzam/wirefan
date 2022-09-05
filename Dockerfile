ARG GOLANG_VERSION="1.18"

FROM golang:$GOLANG_VERSION-alpine as builder
RUN apk --no-cache add git
RUN git clone --branch main https://codeberg.org/peterzam/wireproxy.git
WORKDIR /go/wireproxy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' -o ./wireproxy

FROM scratch
COPY --from=builder /go/wireproxy/wireproxy /
ENTRYPOINT ["/wireproxy","--wg-conf=/wg.conf","--bind=0.0.0.0:1080"]
