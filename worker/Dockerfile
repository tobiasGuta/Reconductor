ARG GO_IMAGE=golang:1.25.7-alpine
ARG PROVIDER_GO_IMAGE=golang:1.26-alpine
ARG NUCLEI_IMAGE=projectdiscovery/nuclei:v3.10.0
ARG NUCLEI_VERSION=v3.10.0
ARG ALPINE_IMAGE=alpine:3.22

FROM ${PROVIDER_GO_IMAGE} AS provider-tools
ARG SUBFINDER_VERSION=v2.14.0
ARG CHAOS_VERSION=v0.5.2
ARG DNSX_VERSION=v1.3.0
ARG NAABU_VERSION=v2.6.1
ARG HTTPX_VERSION=v1.10.0
ARG KATANA_VERSION=v1.6.1
ARG GAU_VERSION=v2.2.4
RUN apk add --no-cache build-base git libpcap-dev
RUN GOBIN=/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
RUN GOBIN=/out go install github.com/projectdiscovery/chaos-client/cmd/chaos@${CHAOS_VERSION}
RUN GOBIN=/out go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}
RUN GOBIN=/out go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}
RUN GOBIN=/out go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}
RUN CGO_ENABLED=1 GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}
RUN GOBIN=/out go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}

FROM ${GO_IMAGE} AS platform-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/platform-worker ./cmd/worker
RUN CGO_ENABLED=0 go build -trimpath -o /out/platform ./cmd/platform
RUN CGO_ENABLED=0 go build -trimpath -o /out/platform-scheduler ./cmd/scheduler

FROM ${ALPINE_IMAGE} AS templates
ARG NUCLEI_TEMPLATES_VERSION=v10.4.3
RUN apk add --no-cache git ca-certificates
RUN git clone --depth 1 --branch ${NUCLEI_TEMPLATES_VERSION} https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates
RUN rm -rf /opt/nuclei-templates/.git
COPY worker/nuclei-templates.version /opt/nuclei-templates/.platform-template-version
RUN test "$(cat /opt/nuclei-templates/.platform-template-version)" = "${NUCLEI_TEMPLATES_VERSION}"

FROM ${NUCLEI_IMAGE}
ARG NUCLEI_VERSION=v3.10.0
ARG SUBFINDER_VERSION=v2.14.0
ARG CHAOS_VERSION=v0.5.2
ARG DNSX_VERSION=v1.3.0
ARG NAABU_VERSION=v2.6.1
ARG HTTPX_VERSION=v1.10.0
ARG KATANA_VERSION=v1.6.1
ARG GAU_VERSION=v2.2.4
ARG NUCLEI_TEMPLATES_VERSION=v10.4.3
RUN apk add --no-cache libpcap
COPY --from=provider-tools /out/ /usr/local/bin/
COPY --from=platform-build /out/platform-worker /usr/local/bin/platform-worker
COPY --from=platform-build /out/platform /usr/local/bin/platform
COPY --from=platform-build /out/platform-scheduler /usr/local/bin/platform-scheduler
COPY --from=templates /opt/nuclei-templates /opt/nuclei-templates
ENV NUCLEI_TEMPLATE_DIR=/opt/nuclei-templates
RUN subfinder -version
RUN chaos -version
RUN dnsx -version
RUN naabu -version
RUN httpx -version
RUN katana -version
RUN gau --version
RUN nuclei -version
LABEL org.opencontainers.image.title="reconductor-worker" \
      io.reconductor.subfinder.version="${SUBFINDER_VERSION}" \
      io.reconductor.chaos.version="${CHAOS_VERSION}" \
      io.reconductor.dnsx.version="${DNSX_VERSION}" \
      io.reconductor.naabu.version="${NAABU_VERSION}" \
      io.reconductor.httpx.version="${HTTPX_VERSION}" \
      io.reconductor.katana.version="${KATANA_VERSION}" \
      io.reconductor.gau.version="${GAU_VERSION}" \
      io.reconductor.nuclei.version="${NUCLEI_VERSION}" \
      io.reconductor.nuclei-templates.version="${NUCLEI_TEMPLATES_VERSION}"
ENTRYPOINT ["/usr/local/bin/platform-worker"]
