APPNAME := $(shell basename `pwd`)
SRCS := $(shell ls *.go | grep -v '_test.go')
LDFLAGS := -ldflags="-s -w -extldflags \"-static\""

.PHONY: all
all: run

.PHONY: clean
clean:
	rm -rf bin/*

.PHONY: fmt
fmt: $(SRCS) 
	go fmt

.PHONY: tidy
tidy: fmt
	go mod tidy

.PHONY: test
test: tidy
	go test -v -cover ./...

.PHONY: build
build: test
	go build $(LDFLAGS) -o bin/$(APPNAME) .

.PHONY: run
run: build
	source env.sh && bin/$(APPNAME)

.PHONY: iam-admin-check
iam-admin-check: build
	source env.sh && bin/$(APPNAME) iam-admin-check
