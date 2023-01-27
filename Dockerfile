FROM golang:1.19-alpine as builder
WORKDIR /app
ADD . .
RUN go mod tidy && CGO_ENABLED=0 go build .

FROM alpine:3.17
WORKDIR /app
ENV PATH=/app:$PATH
RUN apk add --no-cache bash curl
COPY --from=builder /app/sealpack .
