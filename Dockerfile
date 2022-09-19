#https://github.com/docker-library/repo-info/blob/master/repos/golang/remote/1.19-bullseye.md
FROM golang@sha256:e1144f2411ed538b4bcfd6e4a192210bbac7bf6120d64db47c5f1d85f1ea5410 AS build-env

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

#FROM gcr.io/distroless/static-debian10@sha256:f7d14edc27e69f3790cc6bb6c9d24935a84d36df6303547f13c4943dcf87a237
FROM gcr.io/distroless/base-debian11@sha256:33fac4dddb67a1c7d2a93258373c0744776c4ab68af52e1107cc66e3c702c336

ARG BUILD_DATE=2000-01-01T00:00:00:00Z
ARG GIT_CLOSEST_TAG=develop

COPY --from=build-env --chown=nonroot /go/src/github.com/indykite/opa-indykite-plugin/opa /app/opa

# Labels
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=${BUILD_DATE}
LABEL org.label-schema.version=${GIT_CLOSEST_TAG}

USER 65532
ENTRYPOINT ["/app/opa"]
