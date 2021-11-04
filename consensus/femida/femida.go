package femida

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
)

const (
	inMemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	checkpointInterval = 1024        // Number of blocks after which to save the snapshot to the database
	defaultEpochLength = uint64(100) // Default number of blocks of checkpoint to update validatorSet from contract

	extraVanity      = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal        = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
	nextForkHashSize = 4  // Fixed number of extra-data suffix bytes reserved for nextForkHash.

	validatorBytesLength = common.AddressLength
	validatorLimit       = 21
	blockReward          = 2000000000000000000 // 2 ether
)

var (
	uncleHash  = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	diffInTurn = big.NewInt(2)            // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1)            // Block difficulty for out-of-turn signatures

	systemContracts = map[common.Address]bool{
		common.HexToAddress(systemcontracts.ValidatorContract): true,
	}
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errMismatchingEpochValidators is returned if a sprint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingEpochValidators = errors.New("mismatching validator list on epoch block")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errOutOfRangeChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errOutOfRangeChain = errors.New("out of range or non-contiguous chain")

	// errBlockHashInconsistent is returned if an authorization list is attempted to
	// insert an inconsistent block.
	errBlockHashInconsistent = errors.New("the block hash is inconsistent")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
type SignerTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)
type StateFn func(hash common.Hash) (*state.StateDB, error)

func isToSystemContract(to common.Address) bool {
	return systemContracts[to]
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigCache.Add(hash, signer)
	return signer, nil
}

// FemidaRLP returns the rlp bytes which needs to be signed for the femida
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func FemidaRLP(header *types.Header, chainId *big.Int) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, chainId)
	return b.Bytes()
}

// Femida is the consensus engine of ZYX
type Femida struct {
	chainConfig *params.ChainConfig  // Chain config
	config      *params.FemidaConfig // Consensus engine configuration parameters for femida consensus
	genesisHash common.Hash
	db          ethdb.Database // Database to store and retrieve snapshot checkpoints

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining

	signer types.Signer

	val      common.Address // Ethereum address of the signing key
	signFn   SignerFn       // Signer function to authorize hashes with
	signTxFn SignerTxFn

	lock sync.RWMutex // Protects the signer fields

	ethAPI          *ethapi.PublicBlockChainAPI
	validatorSetABI abi.ABI

	stateFn StateFn

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

type Validator struct {
	validator common.Address
	stake     *big.Int
}

// New creates a Femida consensus engine.
func New(
	chainConfig *params.ChainConfig,
	db ethdb.Database,
	ethAPI *ethapi.PublicBlockChainAPI,
	genesisHash common.Hash,
) *Femida {
	// get femida config
	femidaConfig := chainConfig.Femida

	// Set any missing consensus parameters to their defaults
	if femidaConfig != nil && femidaConfig.Epoch == 0 {
		femidaConfig.Epoch = defaultEpochLength
	}

	// Allocate the snapshot caches and create the engine
	recentSnaps, err := lru.NewARC(inMemorySnapshots)
	if err != nil {
		panic(err)
	}
	signatures, err := lru.NewARC(inMemorySignatures)
	if err != nil {
		panic(err)
	}
	vABI, err := abi.JSON(strings.NewReader(validatorSetABI))
	if err != nil {
		panic(err)
	}
	c := &Femida{
		chainConfig:     chainConfig,
		config:          femidaConfig,
		genesisHash:     genesisHash,
		db:              db,
		ethAPI:          ethAPI,
		recentSnaps:     recentSnaps,
		signatures:      signatures,
		validatorSetABI: vABI,
		signer:          types.NewEIP155Signer(chainConfig.ChainID),
	}

	return c
}

func (p *Femida) SetStateFn(fn StateFn) {
	p.stateFn = fn
}

func (p *Femida) IsSystemTransaction(tx *types.Transaction, header *types.Header) (bool, error) {
	// deploy a contract
	if tx.To() == nil {
		return false, nil
	}
	sender, err := types.Sender(p.signer, tx)
	if err != nil {
		return false, errors.New("UnAuthorized transaction")
	}
	if sender == header.Coinbase && isToSystemContract(*tx.To()) && tx.GasPrice().Cmp(big.NewInt(0)) == 0 {
		return true, nil
	}
	return false, nil
}

func (p *Femida) IsSystemContract(to *common.Address) bool {
	if to == nil {
		return false
	}
	return isToSystemContract(*to)
}

// Author implements consensus.Engine, returning the SystemAddress
func (p *Femida) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (p *Femida) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return p.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (p *Femida) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	gopool.Submit(func() {
		for i, header := range headers {
			err := p.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	})
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (p *Femida) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains the vanity, validators and signature.
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// check extra data
	isEpoch := number%p.config.Epoch == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !isEpoch && signersBytes != 0 {
		return errExtraValidators
	}

	if isEpoch && signersBytes%validatorBytesLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil {
			return errInvalidDifficulty
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	return p.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (p *Femida) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	//snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	//if err != nil {
	//	return err
	//}

	// Verify that the gas limit is <= 2^63-1
	capacity := uint64(0x7fffffffffffffff)
	if header.GasLimit > capacity {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, capacity)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}

	// All basic checks passed, verify the seal and return
	return p.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (p *Femida) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := p.recentSnaps.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}

		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(p.config, p.signatures, p.db, hash, p.ethAPI); err == nil {
				log.Trace("Loaded snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// If we're at the genesis, snapshot the initial state.
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				// get checkpoint data
				hash := checkpoint.Hash()

				validatorBytes := checkpoint.Extra[extraVanity : len(checkpoint.Extra)-extraSeal]

				// get validators from headers
				validators, err := ParseValidators(validatorBytes)
				if err != nil {
					return nil, err
				}

				// new snap shot
				snap = newSnapshot(p.config, p.signatures, number, hash, validators, p.ethAPI)
				if err := snap.store(p.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// check if snapshot is nil
	if snap == nil {
		return nil, fmt.Errorf("unknown error while retrieving snapshot at block number %v", number)
	}

	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	snap, err := snap.apply(headers, chain, parents, p.chainConfig.ChainID)
	if err != nil {
		return nil, err
	}
	p.recentSnaps.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(p.db); err != nil {
			return nil, err
		}
		log.Trace("Stored snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (p *Femida) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (p *Femida) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return p.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (p *Femida) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, p.signatures, p.chainConfig.ChainID)
	if err != nil {
		return err
	}

	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}

	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}

	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}

	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !p.fakeDiff {
		inturn := snap.inturn(signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}

	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (p *Femida) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = p.val
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Set the correct difficulty
	header.Difficulty = CalcDifficulty(snap, p.val)

	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity-nextForkHashSize {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-nextForkHashSize-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity-nextForkHashSize]
	nextForkHash := forkid.NextForkHash(p.chainConfig, p.genesisHash, number)
	header.Extra = append(header.Extra, nextForkHash[:]...)

	if number%p.config.Epoch == 0 {
		newValidators, err := p.getCurrentValidators(chain, header)
		if err != nil {
			return err
		}
		// sort validator by address
		sort.Sort(validatorsAscending(newValidators))
		for _, validator := range newValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}

	// add extra seal space
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = p.blockTime(snap, header, parent)

	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (p *Femida) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs *[]*types.Transaction,
	uncles []*types.Header, receipts *[]*types.Receipt, systemTxs *[]*types.Transaction, usedGas *uint64) error {
	// warn if not in majority fork
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	nextForkHash := forkid.NextForkHash(p.chainConfig, p.genesisHash, number)
	if !snap.isMajorityFork(hex.EncodeToString(nextForkHash[:])) {
		log.Debug("there is a possible fork, and your client is not the majority. Please check...", "nextForkHash", hex.EncodeToString(nextForkHash[:]))
	}
	// If the block is a epoch end block, verify the validator list
	// The verification can only be done when the state is ready, it can't be done in VerifyHeader.
	if header.Number.Uint64()%p.config.Epoch == 0 {
		newValidators, err := p.getCurrentValidators(chain, header)
		if err != nil {
			return err
		}
		// sort validator by address
		sort.Sort(validatorsAscending(newValidators))
		validatorsBytes := make([]byte, len(newValidators)*validatorBytesLength)
		for i, validator := range newValidators {
			copy(validatorsBytes[i*validatorBytesLength:], validator.Bytes())
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], validatorsBytes) {
			return errMismatchingEpochValidators
		}
	}
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	cx := chainContext{Chain: chain, femida: p}
	if header.Number.Cmp(common.Big1) == 0 {
		err := p.initContract(state, header, cx, txs, receipts, systemTxs, usedGas, false)
		if err != nil {
			log.Error("init contract failed")
		}
	}
	if header.Difficulty.Cmp(diffInTurn) != 0 {
		spoiledVal := snap.supposeValidator()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == spoiledVal {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			log.Trace("slash validator", "block hash", header.Hash(), "address", spoiledVal)
			//so if validator doesn't signed block recently he will lost his reward.

			//err = p.slash(spoiledVal, state, header, cx, txs, receipts, systemTxs, usedGas, false)

			if err != nil {
				// it is possible that slash validator failed because of the slash channel is disabled.
				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
			}
		}
	}

	val := header.Coinbase
	err = p.distributeIncoming(val, state, header, cx, txs, receipts, systemTxs, usedGas, false)

	if err != nil {
		return err
	}
	if len(*systemTxs) > 0 {
		return errors.New("the length of systemTxs do not match")
	}
	return nil
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (p *Femida) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, []*types.Receipt, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	cx := chainContext{Chain: chain, femida: p}
	if txs == nil {
		txs = make([]*types.Transaction, 0)
	}
	if receipts == nil {
		receipts = make([]*types.Receipt, 0)
	}
	if header.Number.Cmp(common.Big1) == 0 {
		err := p.initContract(state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
		if err != nil {
			log.Error("init contract failed")
		}
	}
	if header.Difficulty.Cmp(diffInTurn) != 0 {
		number := header.Number.Uint64()
		snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
		if err != nil {
			return nil, nil, err
		}
		spoiledVal := snap.supposeValidator()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == spoiledVal {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			//err = p.slash(spoiledVal, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
			if err != nil {
				//it is possible that slash validator failed because of the slash channel is disabled.
				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
			}
		}
	}

	err := p.distributeIncoming(p.val, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
	if err != nil {
		return nil, nil, err
	}

	// should not happen. Once happen, stop the node is better than broadcast the block
	if header.GasLimit < header.GasUsed {
		return nil, nil, errors.New("gas consumption of system txs exceed the gas limit")
	}
	header.UncleHash = types.CalcUncleHash(nil)
	var blk *types.Block
	var rootHash common.Hash
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		rootHash = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
		wg.Done()
	}()
	go func() {
		blk = types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
		wg.Done()
	}()
	wg.Wait()
	blk.SetRoot(rootHash)
	// Assemble and return the final block for sealing
	return blk, receipts, nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (p *Femida) Authorize(val common.Address, signFn SignerFn, signTxFn SignerTxFn) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.val = val
	p.signFn = signFn
	p.signTxFn = signTxFn
}

func (p *Femida) Delay(chain consensus.ChainReader, header *types.Header) *time.Duration {
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil
	}
	delay := p.delayForBlock(snap, header)
	return &delay
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (p *Femida) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if p.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the val fields for the entire sealing procedure
	p.lock.RLock()
	val, signFn := p.val, p.signFn
	p.lock.RUnlock()

	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[val]; !authorized {
		return errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == val {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others")
				return nil
			}
		}
	}

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := p.delayForBlock(snap, header)

	log.Info("Sealing block with", "number", number, "delay", delay, "headerDifficulty", header.Difficulty, "val", val.Hex())

	// Sign all the things!
	sig, err := signFn(accounts.Account{Address: val}, accounts.MimetypeFemida, FemidaRLP(header, p.chainConfig.ChainID))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header, p.chainConfig.ChainID))
		}
	}()

	return nil
}

func (p *Femida) EnoughDistance(chain consensus.ChainReader, header *types.Header) bool {
	snap, err := p.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, nil)
	if err != nil {
		return true
	}
	return snap.enoughDistance(p.val, header)
}

func (p *Femida) IsLocalBlock(header *types.Header) bool {
	return p.val == header.Coinbase
}

func (p *Femida) SignRecently(chain consensus.ChainReader, parent *types.Header) (bool, error) {
	snap, err := p.snapshot(chain, parent.Number.Uint64(), parent.ParentHash, nil)
	if err != nil {
		return true, err
	}

	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[p.val]; !authorized {
		return true, errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	number := parent.Number.Uint64() + 1
	for seen, recent := range snap.Recents {
		if recent == p.val {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				return true, nil
			}
		}
	}
	return false, nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (p *Femida) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := p.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return CalcDifficulty(snap, p.val)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func CalcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (p *Femida) SealHash(header *types.Header) common.Hash {
	return SealHash(header, p.chainConfig.ChainID)
}

// APIs implements consensus.Engine, returning the user facing RPC API to query snapshot.
func (p *Femida) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "femida",
		Version:   "1.0",
		Service:   &API{chain: chain, femida: p},
		Public:    false,
	}}
}

// Close implements consensus.Engine. It's a noop for femida as there are no background threads.
func (p *Femida) Close() error {
	return nil
}

// ==========================  interaction with contract/account =========

type validatorList []Validator

func (e validatorList) Len() int {
	return len(e)
}

func (e validatorList) Less(i, j int) bool {
	result := e[i].stake.Cmp(e[j].stake)
	return result == +1
}

func (e validatorList) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// getCurrentValidators get current validators
func (p *Femida) getCurrentValidators(chain consensus.ChainHeaderReader, header *types.Header) ([]common.Address, error) {
	// method
	method := "getValidators"

	data, err := p.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, err
	}
	// call
	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(systemcontracts.ValidatorContract)

	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return []common.Address{}, consensus.ErrUnknownAncestor
	}
	state, err := p.stateFn(parent.Root)
	if err != nil {
		return []common.Address{}, err
	}

	msg := types.NewMessage(header.Coinbase, &toAddress, 0, new(big.Int), math.MaxUint64, new(big.Int), msgData, *new(types.AccessList), false)
	ret, err := p.ExecuteMsg(msg, state, parent, chainContext{chain, p}, p.chainConfig)

	if err != nil {
		return nil, err
	}

	var (
		ret1 = new([]common.Address)
		ret2 = new([]*big.Int)
	)

	out := []interface{}{ret1, ret2}

	if err := p.validatorSetABI.UnpackIntoInterface(&out, method, ret); err != nil {
		fmt.Println(err)
		return nil, err
	}

	validatorArray := *ret1
	validatorStake := *ret2

	validatorSet := make([]Validator, len(validatorArray))

	for i := 0; i < len(validatorArray); i++ {
		validatorSet[i] = Validator{validatorArray[i], validatorStake[i]}
	}

	sort.Sort(validatorList(validatorSet))

	sliceN := validatorLimit
	if sliceN > len(validatorSet) {
		sliceN = len(validatorSet)
	}

	var sortedValidators []common.Address
	for i := 0; i < sliceN; i++ {
		sortedValidators = append(sortedValidators, validatorSet[i].validator)
	}

	return sortedValidators, nil
}

func (p *Femida) distributeIncoming(val common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	coinbase := header.Coinbase
	balance := state.GetBalance(consensus.SystemAddress)
	validatorContractBalance := state.GetBalance(common.HexToAddress(systemcontracts.ValidatorContract))
	currentBlockReward := big.NewInt(blockReward)
	if validatorContractBalance.Cmp(common.Big0) <= 0 && balance.Cmp(common.Big0) <= 0 {
		return nil
	}

	if validatorContractBalance.Cmp(common.Big0) < blockReward {
		currentBlockReward = validatorContractBalance
	}

	state.SetBalance(consensus.SystemAddress, big.NewInt(0))
	state.AddBalance(coinbase, balance)

	log.Trace("distribute to validator contract", "block hash", header.Hash(), "blockReward", currentBlockReward, "amount", balance)
	return p.distributeToValidator(balance, val, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// slash spoiled validators
//func (p *Femida) slash(spoiledVal common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
//	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
//	// method
//	method := "slashValidator"
//
//	// get packed data
//	data, err := p.validatorSetABI.Pack(method,
//		spoiledVal,
//	)
//	if err != nil {
//		log.Error("Unable to pack tx for slash", "error", err)
//		return err
//	}
//	// get system message
//	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.ValidatorContract), data, common.Big0)
//	// apply message
//	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
//}

// init contract
func (p *Femida) initContract(state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "init"
	// contracts
	contracts := []string{
		systemcontracts.ValidatorContract,
	}
	// get packed data
	data, err := p.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for init validator set", "error", err)
		return err
	}
	for _, c := range contracts {
		msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(c), data, common.Big0)
		// apply message
		log.Trace("init contract", "block hash", header.Hash(), "contract", c)
		err = p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
		if err != nil {
			return err
		}
	}
	return nil
}

// slash spoiled validators
func (p *Femida) distributeToValidator(amount *big.Int, validator common.Address,
	state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {

	// method
	method := "deposit"

	// get packed data
	data, err := p.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.ValidatorContract), data, amount)
	// apply message
	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}
