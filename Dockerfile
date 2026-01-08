# Stage 1: Build step-ca with acmeproxy plugin

FROM golang:1.25.5-trixie AS build

WORKDIR /build

COPY . .

RUN make

# Stage 2: Copy the build artifacts to final image

FROM chainguard/wolfi-base:latest

WORKDIR /acmeproxy
RUN chown -R nonroot:nonroot /acmeproxy/

COPY --from=build --chown=nonroot:nonroot /build/step-ca .

# KV store mount point
RUN mkdir /acmeproxy/db && chown nonroot:nonroot /acmeproxy/db

# ca.json  mount point
RUN mkdir /acmeproxy/config && chown nonroot:nonroot /acmeproxy/config

USER nonroot
EXPOSE 443

ENTRYPOINT [ "/acmeproxy/step-ca" ]
CMD [ "/acmeproxy/config/ca.json" ]
