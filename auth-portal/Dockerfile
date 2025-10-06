# ---- builder ----
FROM golang:1.23.12-alpine3.21 AS build
WORKDIR /src

# Tools needed for fetching modules over HTTPS
RUN apk add --no-cache git ca-certificates openssl=3.3.5-r0 && update-ca-certificates

# 1) Prime module cache (copies go.mod/go.sum if present)
COPY go.* ./
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org
RUN go mod download

# 2) Copy sources and ensure sums are tidy
COPY . .
RUN go mod tidy -compat=1.23

# 3) Build static binary (verbose, no VCS scan)
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -v -x -buildvcs=false -trimpath -ldflags="-s -w" -o /out/auth-portal .

# ---- runtime ----
FROM alpine:3.21
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata openssl=3.3.5-r0 && apk --no-cache upgrade musl && update-ca-certificates

COPY --from=build /out/auth-portal /app/auth-portal
COPY templates ./templates
COPY static ./static

RUN adduser -D -H -u 10001 app && chown -R app:app /app
USER 10001:10001

EXPOSE 8080
ENTRYPOINT ["/app/auth-portal"]

