FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache git
RUN go mod tidy && CGO_ENABLED=0 go build .

FROM scratch
WORKDIR /app
ENV PATH=/app:$PATH
COPY --from=builder /app/sealpack .
