VERSION ?= $(shell git describe --tags --always)
BIN     ?= ./dmarcator

all: dmarcator dmarcator.8

dmarcator: go.mod go.sum *.go
	go build -ldflags '-X main.version=$(VERSION)'

dmarcator.8: $(BIN) dmarcator.h2m
	help2man --include=dmarcator.h2m --no-info --section=8 $(BIN) -o $@

check:
	! gofmt -s -d . | grep ''
	go vet ./...
	go test -cover ./...

clean:
	rm -f dmarcator dmarcator.8

.PHONY: all check clean
