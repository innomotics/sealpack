#!/bin/bash

GOOS=linux CGO_ENABLED=0 go build -o main .
chmod 0755 main
zip downloader.zip main