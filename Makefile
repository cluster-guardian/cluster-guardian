BINARY  := cluster-guardian
VERSION ?= dev
LDFLAGS := -s -w -X github.com/cluster-guardian/cluster-guardian/cmd.Version=$(VERSION)

.PHONY: build test vet lint fmt docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

clean:
	rm -f $(BINARY)
