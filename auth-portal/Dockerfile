# ---- builder ----
FROM golang:1.25.7-alpine3.22 AS build
WORKDIR /src

# Tools needed for fetching modules over HTTPS
RUN apk upgrade --no-cache busybox && \
    apk add --no-cache ca-certificates git openssl && update-ca-certificates

# 1) Prime module cache (copies go.mod/go.sum if present)
COPY go.mod go.sum ./
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org
RUN go mod download

# 2) Copy sources and ensure sums are tidy (explicit paths avoid pulling unwanted files)
COPY *.go ./
COPY providers ./providers
COPY oauth ./oauth
COPY configstore ./configstore
COPY health ./health
COPY static ./static
COPY templates ./templates
RUN go mod tidy -compat=1.25

# 3) Build static binary (verbose, no VCS scan)
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -v -x -buildvcs=false -trimpath -ldflags="-s -w" -o /out/auth-portal .

# ---- runtime ----
FROM alpine:3.21
WORKDIR /app

RUN apk upgrade --no-cache busybox && \
    apk add --no-cache ca-certificates openssl=3.3.6-r0 tzdata && \
    apk --no-cache upgrade musl && update-ca-certificates

COPY --from=build /out/auth-portal /app/auth-portal
COPY templates ./templates
COPY static ./static

RUN adduser -D -H -u 10001 app && chown -R app:app /app
USER 10001:10001

EXPOSE 8080
ENTRYPOINT ["/app/auth-portal"]



