#https://github.com/docker-library/repo-info/blob/master/repos/golang/remote/1.20.6-bullseye.md
FROM golang:1.22.1-bullseye@sha256:dcff0d950cb4648fec14ee51baa76bf27db3bb1e70a49f75421a8828db7b9910 AS build-env

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
FROM gcr.io/distroless/base-debian11:nonroot@sha256:1a8ece87bd75cde87d0484ef48eb60ea25811baf90967265956ae4fa2098dd9d

ARG BUILD_DATE=2000-01-01T00:00:00:00Z
ARG GIT_CLOSEST_TAG=develop

COPY --from=build-env --chown=nonroot /go/src/github.com/indykite/opa-indykite-plugin/opa /app/opa

# Labels
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=${BUILD_DATE}
LABEL org.label-schema.version=${GIT_CLOSEST_TAG}

USER 65532
ENTRYPOINT ["/app/opa"]
