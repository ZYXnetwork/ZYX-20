package femida

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/rand"
	"time"
)

const (
	wiggleTime         = uint64(1) // second, Random delay (per signer) to allow concurrent signers
	initialBackOffTime = uint64(1) // second

	wiggleTimeBeforeFork       = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
	fixedBackOffTimeBeforeFork = 200 * time.Millisecond
)

func (p *Femida) delayForBlock(snap *Snapshot, header *types.Header) time.Duration {
	delay := time.Until(time.Unix(int64(header.Time), 0)) // nolint: gosimple
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTimeBeforeFork
		delay += time.Duration(fixedBackOffTimeBeforeFork) + time.Duration(rand.Int63n(int64(wiggle)))
	}
	return delay
}

func (p *Femida) blockTime(snap *Snapshot, header, parent *types.Header) uint64 {
	blockTime := parent.Time + p.config.Period
	blockTime = blockTime + backOffTime(snap, p.val)
	return blockTime
}

func backOffTime(snap *Snapshot, val common.Address) uint64 {
	if snap.inturn(val) {
		return 0
	} else {
		idx := snap.indexOfVal(val)
		if idx < 0 {
			// The backOffTime does not matter when a validator is not authorized.
			return 0
		}
		s := rand.NewSource(int64(snap.Number))
		r := rand.New(s)
		n := len(snap.Validators)
		backOffSteps := make([]uint64, 0, n)
		for idx := uint64(0); idx < uint64(n); idx++ {
			backOffSteps = append(backOffSteps, idx)
		}
		r.Shuffle(n, func(i, j int) {
			backOffSteps[i], backOffSteps[j] = backOffSteps[j], backOffSteps[i]
		})
		delay := initialBackOffTime + backOffSteps[idx]*wiggleTime
		return delay
	}
}
