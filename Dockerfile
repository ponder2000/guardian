FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG AUTHOR="Jay Saha"

RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X 'main.buildTime=${BUILD_TIME}' -X 'main.author=${AUTHOR}'" \
    -o /guardian-manager ./cmd/guardian-manager/

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S guardian && adduser -S guardian -G guardian

WORKDIR /app

COPY --from=builder /guardian-manager .

RUN mkdir -p /app/data && chown guardian:guardian /app/data

USER guardian

EXPOSE 8080

VOLUME ["/app/data"]

ENTRYPOINT ["./guardian-manager"]
CMD ["--db", "/app/data/guardian-manager.db", "--listen", ":8080"]
