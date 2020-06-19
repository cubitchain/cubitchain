.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/cubitchain/cubitchain/cmd/swarm
	go build -o bin/geth     github.com/cubitchain/cubitchain/cmd/geth
	go build -o bin/bootnode github.com/cubitchain/cubitchain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/cubitchain/cubitchain/swarm/...
