# Stage 1: Build step-ca with acme-proxy plugin

FROM golang:1.25.5-trixie AS build

WORKDIR /build

COPY . .

RUN make

# Stage 2: Copy the build artifacts to final image

FROM chainguard/wolfi-base:latest

WORKDIR /acme-proxy
RUN chown -R nonroot:nonroot /acme-proxy/

COPY --from=build --chown=nonroot:nonroot /build/step-ca .

# KV store mount point
RUN mkdir /acme-proxy/db && chown nonroot:nonroot /acme-proxy/db

# ca.json  mount point
RUN mkdir /acme-proxy/config && chown nonroot:nonroot /acme-proxy/config

USER nonroot
EXPOSE 443

ENTRYPOINT [ "/acme-proxy/step-ca" ]
CMD [ "/acme-proxy/config/ca.json" ]
