FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod openfir.go openfir_test.go ./
COPY internal/ internal/
RUN go test ./... && CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/openfir .

FROM scratch
COPY --from=build /out/openfir /usr/local/bin/openfir
COPY LICENSE /usr/share/licenses/openfir/LICENSE
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/openfir"]
CMD ["-help"]
