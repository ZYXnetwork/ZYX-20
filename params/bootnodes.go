// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{
	"enode://ef4e9dc61bd9308b8a9d9f83469e17567e795ca4d9a5bb680a20a7a8960b7a31bd806313f8e41da65404febcd4f11c0805f0fda24bc80aa04df0164bd0fc6d33@23.88.111.237:30322",
	"enode://1af558f50040efa8f0cb4ad0534e5e007396b598b351ae2f08078855d5518de571cff6813dd06d4491b54f92ead9ff775d2352c2c7b61c1c10e1eaf1c6f5cb24@18.166.67.20:30322",
	"enode://6f568031a9d5f4be774b031a6364c3e6fa4c87d1f0e8c195466ce08b2271820e1154ecd1e91095400ccaddc21bd493ab8fdd0456884b45edf69db9889c762d53@95.217.238.98:30322",
}


// MinervaBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Minerva test network.
var MinervaBootnodes = []string{
	"enode://9e85625008b3c4e39875b9ee9a002913561c926bd4c9614e8785b0deea70b87ba47b34e6eadb9463d964725cdbd8a68bd370ea9ba15487ea90fea91505dbd741@138.201.141.120:30322",
	"enode://5981dc911ec21277d44b3b185bb96309a3cd2598007b2d69777ef39e339690aba2f97e0813a15bb54f0a3ae446e845222e42dc3a29e4b89e0541c89732bfaad4@185.203.118.4:30322",
}


// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var V5Bootnodes = []string{
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	//case MainnetGenesisHash:
	//	net = "minerva"
	case MinervaGenesisHash:
		net = "minerva"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
