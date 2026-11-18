FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod openfir.go openfir_test.go ./
COPY internal/ internal/
RUN go test ./... && CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/openfir .

# Pin the upstream release and verify the executable before packaging it.
RUN case "$TARGETARCH" in \
      amd64) digest=fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2 ;; \
      arm64) digest=e7c52241299fe85aba11e9d36e85d8d88ddbb5799ac0e33d272219d20e313bab ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    wget -qO /out/hysteria "https://github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hysteria-linux-$TARGETARCH" && \
    echo "$digest  /out/hysteria" | sha256sum -c - && chmod 0755 /out/hysteria

FROM scratch
ENV PATH=/usr/local/bin
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY LICENSE docker/LICENSE-hysteria /usr/share/licenses/openfir/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/openfir"]
CMD ["-help"]
