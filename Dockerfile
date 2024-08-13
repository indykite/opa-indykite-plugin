#https://github.com/docker-library/repo-info/blob/master/repos/golang/remote/1.20.6-bullseye.md
FROM golang:1.22.6-bullseye@sha256:825f81571780b54e553c4d7f21081efd47cd125dd7a8b3343a4591aa02f4816a AS build-env

ARG SHORT_SHA=0000000
ARG TAG_NAME
ARG BUILD_DATE=2000-01-01T00:00:00:00Z
ARG SERVICE_NAME=indykite-agent

WORKDIR /go/src/github.com/indykite/opa-indykite-plugin
COPY . .

ENV GO111MODULE=on

#RUN go build -mod mod -o opa -ldflags "-w -s -extldflags \"-static\" -X github.com/open-policy-agent/opa/version.Vcs=${SHORT_SHA} -X github.com/open-policy-agent/opa/version.Version=${TAG_NAME} -X github.com/open-policy-agent/opa/version.Timestamp=${BUILD_DATE} -X github.com/open-policy-agent/opa/version.Hostname=${SERVICE_NAME}" .
RUN go build -mod mod -o opa -ldflags "-w -s \
    -X github.com/open-policy-agent/opa/version.Vcs=${SHORT_SHA} \
    -X github.com/open-policy-agent/opa/version.Version=${TAG_NAME} \
    -X github.com/open-policy-agent/opa/version.Timestamp=${BUILD_DATE} \
    -X github.com/open-policy-agent/opa/version.Hostname=${SERVICE_NAME}" .

# gcr.io/distroless/base-debian11:nonroot
FROM gcr.io/distroless/base-debian11:nonroot@sha256:68b0f492c1eb077f71d384b544456dac4afb282372966917df32b3923f65ad0d

ARG BUILD_DATE=2000-01-01T00:00:00:00Z
ARG GIT_CLOSEST_TAG=develop

COPY --from=build-env --chown=nonroot /go/src/github.com/indykite/opa-indykite-plugin/opa /app/opa

# Labels
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=${BUILD_DATE}
LABEL org.label-schema.version=${GIT_CLOSEST_TAG}

USER 65532
ENTRYPOINT ["/app/opa"]
