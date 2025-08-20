FROM golang:1.22-alpine

WORKDIR /app

# ✅ Copy all code (go.mod, go.sum, main.go, etc.)
COPY . .

# ✅ Tidy now that all source is in place
RUN go mod tidy

# ✅ Build the binary
RUN go build -o ldap-sync .

CMD ["./ldap-sync"]