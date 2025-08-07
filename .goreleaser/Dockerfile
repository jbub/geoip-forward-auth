FROM alpine:3.22
LABEL maintainer="Juraj Bubniak <juraj.bubniak@gmail.com>"

RUN addgroup -S geoip-forward-auth \
    && adduser -D -S -s /sbin/nologin -G geoip-forward-auth geoip-forward-auth

RUN apk --no-cache add tzdata ca-certificates

COPY geoip-forward-auth /bin

USER geoip-forward-auth

ENTRYPOINT ["geoip-forward-auth"]
CMD ["server"]
