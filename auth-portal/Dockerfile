# ---- builder ----
FROM dhi.io/golang:1.26.2-alpine3.23-dev AS build
WORKDIR /src

# Tools needed for fetching modules over HTTPS
RUN apk add --no-cache "busybox>=1.37.0-r27" && \
    apk add --no-cache ca-certificates git tzdata && update-ca-certificates

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
COPY ldapsync ./ldapsync
COPY static ./static
COPY templates ./templates
RUN go mod tidy -compat=1.26

# 3) Build static binary (verbose, no VCS scan)
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -v -x -buildvcs=false -trimpath -ldflags="-s -w" -o /out/auth-portal .

# ---- runtime ----
FROM dhi.io/alpine-base:3.23-alpine3.23
WORKDIR /app

COPY --from=build --chown=65532:65532 /out/auth-portal /app/auth-portal
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --chown=65532:65532 templates ./templates
COPY --chown=65532:65532 static ./static

USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/auth-portal"]



