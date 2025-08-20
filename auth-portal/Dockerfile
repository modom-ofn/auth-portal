# ---- builder ----
FROM golang:1.23.10-alpine3.21 AS build
WORKDIR /src

# 1) Prime module cache (optional if go.sum doesn’t exist yet)
COPY go.mod ./
# COPY go.sum ./           # include only if it exists in your context
RUN go mod download

# 2) Now copy the actual sources, then tidy to compute go.sum fully
COPY . .
RUN go mod tidy

# 3) Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/auth-portal .

# ---- runtime ----
FROM alpine:3.21
WORKDIR /app

RUN apk add --no-cache ca-certificates && apk --no-cache upgrade musl

COPY --from=build /out/auth-portal /app/auth-portal
COPY templates ./templates
COPY static ./static

RUN adduser -D -H -u 10001 app && chown -R app:app /app
USER 10001:10001

EXPOSE 8080
ENTRYPOINT ["/app/auth-portal"]