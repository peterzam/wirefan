ARG GOLANG_VERSION="1.19.3"

FROM golang:$GOLANG_VERSION-alpine as builder
RUN apk --no-cache add git
RUN git clone --branch main https://codeberg.org/peterzam/wirefan.git
WORKDIR /go/wirefan
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' -o ./wirefan

FROM scratch
COPY --from=builder /go/wirefan/wirefan /
ENTRYPOINT ["/wirefan","--wg-conf=/wg.conf","--bind=0.0.0.0:1080"]
