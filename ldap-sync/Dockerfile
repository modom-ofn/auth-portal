# ---- builder ----
FROM golang:1.23.12-alpine3.21 AS build
WORKDIR /src

# copy only go.mod first (no go.sum yet)
COPY go.mod ./
RUN go mod download

# now copy source and finalize deps
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ldap-sync .

# ---- runtime ----
FROM alpine:3.21
WORKDIR /app
RUN apk add --no-cache ca-certificates && apk --no-cache upgrade musl
COPY --from=build /out/ldap-sync /app/ldap-sync
USER 65532:65532
ENTRYPOINT ["/app/ldap-sync"]
