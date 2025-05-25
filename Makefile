VERSION ?= $(shell git describe --tags --always)

all: dmarcator

dmarcator: go.mod go.sum *.go
	go build -ldflags '-X main.version=$(VERSION)'

clean:
	rm -f dmarcator

.PHONY: all clean
