.PHONY: build test clean

build:
	go generate ./...
	go build -o machoproxy .

test: build
	go test ./...

clean:
	go clean
