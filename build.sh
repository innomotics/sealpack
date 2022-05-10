#!/bin/bash

GOOS=linux CGO_ENABLED=0 go build main.go
chmod 0755 main
zip downloader.zip main