#https://github.com/docker-library/repo-info/blob/master/repos/golang/remote/1.19-bullseye.md
FROM golang@sha256:685a22e459f9516f27d975c5cc6accc11223ee81fdfbbae60e39cc3b87357306 AS build-env

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

RUN ls -lh /go/src/github.com/indykite/opa-indykite-plugin/

FROM gcr.io/distroless/base-debian11@sha256:df13a91fd415eb192a75e2ef7eacf3bb5877bb05ce93064b91b83feef5431f37

ARG BUILD_DATE=2000-01-01T00:00:00:00Z
ARG GIT_CLOSEST_TAG=develop

COPY --from=build-env --chown=nonroot /go/src/github.com/indykite/opa-indykite-plugin/opa /app/opa

# Labels
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=${BUILD_DATE}
LABEL org.label-schema.version=${GIT_CLOSEST_TAG}

USER 65532
ENTRYPOINT ["/app/opa"]
