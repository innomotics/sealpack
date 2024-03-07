FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY *.go go.mod go.sum /app/
COPY common/ /app/common
COPY cmd/ /app/cmd
COPY aws/ /app/aws
RUN ls -alh
RUN apk add --no-cache git
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
RUN go mod tidy && cd cmd && CGO_ENABLED=0 go build -o /app/sealpack .

FROM scratch
WORKDIR /app
ENV PATH=/app:$PATH
COPY --from=builder /etc/passwd /etc/passwd
USER nonroot
COPY --from=builder /app/sealpack .
ENTRYPOINT ["/app/sealpack"]
