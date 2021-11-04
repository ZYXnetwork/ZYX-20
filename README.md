## Zyx Network


[![API Reference](
https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667
)](https://pkg.go.dev/github.com/ethereum/go-ethereum?tab=doc)
[![Discord](https://img.shields.io/badge/discord-join%20chat-blue.svg)](https://discord.gg/h3GeZKH2DQ)



## Building the source

Many of the below are the same as or similar to go-ethereum.

For prerequisites and detailed build instructions please read the [Installation Instructions](https://geth.ethereum.org/docs/install-and-build/installing-geth).

Building `geth` requires both a Go (version 1.14 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run.

```shell
make geth
```

## A Full node on the Zyx Mainnet

Steps:

1. Download the binary [release](https://github.com/ZYXnetwork/ZYX-20/releases), or compile the binary by `make geth`.
2. Start fullnode: `./geth`.

*Note: This node is not compatible with Minerva testnet, so for starting full node in testnet use [ZYX-20-v1](https://github.com/ZYXnetwork/ZYX-20-v1)*

## Specifation

At the current moment, Zyx mainnet works on the Minerva consensus engine.
