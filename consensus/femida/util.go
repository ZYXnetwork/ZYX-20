package femida

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
)

func (p *Femida) getSystemMessage(from, toAddress common.Address, data []byte, value *big.Int) callmsg {
	return callmsg{
		ethereum.CallMsg{
			From:     from,
			Gas:      math.MaxUint64 / 2,
			GasPrice: big.NewInt(0),
			Value:    value,
			To:       &toAddress,
			Data:     data,
		},
	}
}

func (p *Femida) applyTransaction(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainContext core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt,
	receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool,
) (err error) {
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), msg.Gas(), msg.GasPrice(), msg.Data())
	expectedHash := p.signer.Hash(expectedTx)

	if msg.From() == p.val && mining {
		expectedTx, err = p.signTxFn(accounts.Account{Address: msg.From()}, expectedTx, p.chainConfig.ChainID)
		if err != nil {
			return err
		}
	} else {
		if receivedTxs == nil || len(*receivedTxs) == 0 || (*receivedTxs)[0] == nil {
			return errors.New("supposed to get a actual transaction, but get none")
		}
		actualTx := (*receivedTxs)[0]
		if !bytes.Equal(p.signer.Hash(actualTx).Bytes(), expectedHash.Bytes()) {
			return fmt.Errorf("expected tx hash %v, get %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s", expectedHash.String(), actualTx.Hash().String(),
				expectedTx.Nonce(),
				expectedTx.To().String(),
				expectedTx.Value().String(),
				expectedTx.Gas(),
				expectedTx.GasPrice().String(),
				hex.EncodeToString(expectedTx.Data()),
			)
		}
		expectedTx = actualTx
		// move to next
		*receivedTxs = (*receivedTxs)[1:]
	}
	state.Prepare(expectedTx.Hash(), common.Hash{}, len(*txs))
	gasUsed, err := applyMessage(msg, state, header, p.chainConfig, chainContext)
	if err != nil {
		return err
	}
	*txs = append(*txs, expectedTx)
	var root []byte
	if p.chainConfig.IsByzantium(header.Number) {
		state.Finalise(true)
	} else {
		root = state.IntermediateRoot(p.chainConfig.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gasUsed
	receipt := types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = expectedTx.Hash()
	receipt.GasUsed = gasUsed

	//// Set the receipt logs and create a bloom for filtering
	receipt.Logs = state.GetLogs(expectedTx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = state.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(state.TxIndex())
	*receipts = append(*receipts, receipt)
	state.SetNonce(msg.From(), nonce+1)
	return nil
}

// ===========================     utility function        ==========================
// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

// chain context
type chainContext struct {
	Chain  consensus.ChainHeaderReader
	femida consensus.Engine
}

func (c chainContext) Engine() consensus.Engine {
	return c.femida
}

func (c chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.Chain.GetHeader(hash, number)
}

// callmsg implements core.Message to allow passing it as a transaction simulator.
type callmsg struct {
	ethereum.CallMsg
}

func (m callmsg) From() common.Address { return m.CallMsg.From }
func (m callmsg) Nonce() uint64        { return 0 }
func (m callmsg) CheckNonce() bool     { return false }
func (m callmsg) To() *common.Address  { return m.CallMsg.To }
func (m callmsg) GasPrice() *big.Int   { return m.CallMsg.GasPrice }
func (m callmsg) Gas() uint64          { return m.CallMsg.Gas }
func (m callmsg) Value() *big.Int      { return m.CallMsg.Value }
func (m callmsg) Data() []byte         { return m.CallMsg.Data }

// apply message
func applyMessage(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainConfig *params.ChainConfig,
	chainContext core.ChainContext,
) (uint64, error) {
	// Create a new context to be used in the EVM environment
	context := core.NewEVMBlockContext(header, chainContext, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, vm.TxContext{Origin: msg.From(), GasPrice: big.NewInt(0)}, state, chainConfig, vm.Config{})
	// Apply the transaction to the current state (included in the env)
	ret, returnGas, err := vmenv.Call(
		vm.AccountRef(msg.From()),
		*msg.To(),
		msg.Data(),
		msg.Gas(),
		msg.Value(),
	)
	if err != nil {
		log.Error("apply message failed", "msg", string(ret), "err", err)
	}
	return msg.Gas() - returnGas, err
}


// ExecuteMsg executes transaction sent to system contracts.
func (p *Femida) ExecuteMsg(msg core.Message, state *state.StateDB, header *types.Header, chainContext core.ChainContext, chainConfig *params.ChainConfig) (ret []byte, err error) {
	// Set gas price to zero
	context := core.NewEVMBlockContext(header, chainContext, &(header.Coinbase))
	vmenv := vm.NewEVM(context, vm.TxContext{Origin: msg.From(), GasPrice: big.NewInt(0)}, state, chainConfig, vm.Config{})

	ret, _, err = vmenv.Call(vm.AccountRef(msg.From()), *msg.To(), msg.Data(), msg.Gas(), msg.Value())

	return ret, err
}