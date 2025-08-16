FROM golang:1.25 AS builder
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-extldflags '-static'" -tags netgo -o /bin/geoip-forward-auth

FROM alpine:3.22
LABEL maintainer="Juraj Bubniak <juraj.bubniak@gmail.com>"

RUN addgroup -S geoip-forward-auth \
    && adduser -D -S -s /sbin/nologin -G geoip-forward-auth geoip-forward-auth

RUN apk --no-cache add tzdata ca-certificates

COPY --from=builder /bin/geoip-forward-auth /bin

USER geoip-forward-auth

ENTRYPOINT ["geoip-forward-auth"]
CMD ["server"]
