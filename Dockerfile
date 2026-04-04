FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git dpkg make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Extract version from Makefile — single source of truth
RUN echo "VERSION=$(grep -m1 '^VERSION' Makefile | sed 's/.*?= *//')" > /tmp/buildargs

ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG AUTHOR="Jay Saha"

# Build guardian-manager natively for the target platform
RUN . /tmp/buildargs && CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X 'main.buildTime=${BUILD_TIME}' -X 'main.author=${AUTHOR}'" \
    -o /guardian-manager ./cmd/guardian-manager/

# Build the .deb package for the target arch
RUN NATIVE_ARCH=$(go env GOARCH) && make package-deb DEB_ARCH=${NATIVE_ARCH}

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /guardian-manager .

# Copy .deb package into the final image
COPY --from=builder /src/bin/guardian_*.deb /app/deb/
RUN cd /app/deb && ln -sf guardian_*.deb guardian.deb

RUN mkdir -p /app/data

EXPOSE 8080

VOLUME ["/app/data"]

ENTRYPOINT ["./guardian-manager"]
CMD ["--db", "/app/data/guardian-manager.db", "--listen", ":8080", "--deb-dir", "/app/deb"]
