# Stage 1: Build step-ca with acme-proxy plugin

FROM golang:1.26.2-trixie AS build

WORKDIR /build

COPY . .

RUN make

# Stage 2: Copy the build artifacts to final image

FROM chainguard/wolfi-base:latest

WORKDIR /opt/acme-proxy
RUN chown -R nonroot:nonroot /opt/acme-proxy/

COPY --from=build --chown=nonroot:nonroot /build/step-ca .
RUN apk add --no-cache pcsc-lite

# KV store mount point
RUN mkdir /opt/acme-proxy/db && chown nonroot:nonroot /opt/acme-proxy/db

USER nonroot
EXPOSE 443

ENTRYPOINT [ "/opt/acme-proxy/step-ca" ]
CMD [ "/opt/acme-proxy/ca.json" ]
