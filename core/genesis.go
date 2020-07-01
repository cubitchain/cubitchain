// Copyright 2014 The cubitchain Authors
// This file is part of the cubitchain library.
//
// The cubitchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cubitchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cubitchain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cubitchain/cubitchain/crypto"
	"github.com/cubitchain/cubitchain/p2p/enode"
	"math/big"
	"strings"

	"github.com/cubitchain/cubitchain/common"
	"github.com/cubitchain/cubitchain/common/hexutil"
	"github.com/cubitchain/cubitchain/common/math"
	"github.com/cubitchain/cubitchain/core/rawdb"
	"github.com/cubitchain/cubitchain/core/state"
	"github.com/cubitchain/cubitchain/core/types"
	"github.com/cubitchain/cubitchain/ethdb"
	"github.com/cubitchain/cubitchain/log"
	"github.com/cubitchain/cubitchain/params"
	"github.com/cubitchain/cubitchain/rlp"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	StateRoot  common.Hash         `json:"stateRoot"`
	Alloc      GenesisAlloc        `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.CircumChainConfig, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, params.GenesisBlockNumber)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}
	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}
	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)

		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}
	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {

		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {

		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	default:
		return params.CircumChainConfig
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = ethdb.NewMemDatabase()
	}

	statedb, _ := state.New(g.StateRoot, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance, big.NewInt(1))
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)

	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, false)
	block := types.NewBlock(head, nil, nil, nil)

	return block
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.NumberU64() != params.GenesisBlockNumber {
		return nil, fmt.Errorf("can't commit genesis block with number != %d", params.GenesisBlockNumber)
	}
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}}}
	return g.MustCommit(db)
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	alloc := decodePrealloc(mainnetAllocData)
	alloc[common.BytesToAddress(params.MasterndeContractAddress.Bytes())] = masternodeContractAccount(params.MainnetMasternodes)
	alloc[common.HexToAddress("0xd77BfC32a627B730ea12E1a5bd4b3A3c8E443d92")] = GenesisAccount{
		Balance: new(big.Int).Mul(big.NewInt(57e+8), big.NewInt(1e+15)),
	}
	config := params.CircumChainConfig
	var witnesses []string
	for _, n := range params.MainnetMasternodes {
		node := enode.MustParseV4(n)
		pubkey := node.Pubkey()
		addr := crypto.PubkeyToAddress(*pubkey)
		if _, ok := alloc[addr]; !ok {
			alloc[addr] = GenesisAccount{
				Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e+16)),
			}
		}
		xBytes := pubkey.X.Bytes()
		var x [32]byte
		copy(x[32-len(xBytes):], xBytes[:])
		id1 := common.BytesToHash(x[:])
		id := fmt.Sprintf("%x", id1[:8])
		witnesses = append(witnesses, id)
	}
	config.Circum.Witnesses = witnesses
	return &Genesis{
		Config:     config,
		Nonce:      1,
		Timestamp:  1583712800,
		GasLimit:   10000000,
		Difficulty: big.NewInt(1),
		Alloc:      alloc,
		Number:     params.GenesisBlockNumber,
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	alloc := decodePrealloc(testnetAllocData)
	alloc[common.BytesToAddress(params.MasterndeContractAddress.Bytes())] = masternodeContractAccount(params.TestnetMasternodes)
	alloc[common.HexToAddress("0x4b961Cc393e08DF94F70Cad88142B9962186FfD1")] = GenesisAccount{
		Balance: new(big.Int).Mul(big.NewInt(1e+11), big.NewInt(1e+15)),
	}
	config := params.TestnetChainConfig
	var witnesses []string
	for _, n := range params.TestnetMasternodes {
		node := enode.MustParseV4(n)
		pubkey := node.Pubkey()
		//addr := crypto.PubkeyToAddress(*pubkey)
		//if _, ok := alloc[addr]; !ok {
		//	alloc[addr] = GenesisAccount{
		//		Balance: new(big.Int).Mul(big.NewInt(1e+16), big.NewInt(1e+15)),
		//	}
		//}
		xBytes := pubkey.X.Bytes()
		var x [32]byte
		copy(x[32-len(xBytes):], xBytes[:])
		id1 := common.BytesToHash(x[:])
		id := fmt.Sprintf("%x", id1[:8])
		witnesses = append(witnesses, id)
	}
	config.Circum.Witnesses = witnesses
	return &Genesis{
		Config:     config,
		Nonce:      66,
		Timestamp:  1531551970,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      alloc,
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DefaultGoerliGenesisBlock returns the Görli network genesis block.
func DefaultGoerliGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.GoerliChainConfig,
		Timestamp:  1548854791,
		ExtraData:  hexutil.MustDecode("0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   10485760,
		Difficulty: big.NewInt(1),
		// Alloc:      decodePrealloc(goerliAllocData),
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block. Note, this must
// be seeded with the
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, 65)...),
		GasLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}

func masternodeContractAccount(masternodes []string) GenesisAccount {
	data := make(map[common.Hash]common.Hash)

	data[common.HexToHash("0x0b661fcad4c0846e3ce383f850f263b279652e74f5a462f3f88039aa0fc00f4a")] = common.HexToHash("0x013e2e93950c015fd47d13fbe556d8bc9f8175c48c314864a5b7cab6ab62f9fe")
	data[common.HexToHash("0x1623a934daba0d666b4573d50a1fbe62b95639af96898a07387067534e91c158")] = common.HexToHash("0x00000000000000000000000000000000056b815c256ec67168a34ce81daa4602")
	data[common.HexToHash("0xda0f5d16ebbad5ec6deb9b44e24df3a369aceaded22ef1471dba34965a53c188")] = common.HexToHash("0xce04367390f08a914c965aa571e937bd0c0b450174ae28e4de45dce7356a10b3")
	data[common.HexToHash("0xa728b64b8eeeae868982d0e84701b1e766931dfc43b5eff0e6f04b67eaf5722a")] = common.HexToHash("0x000000000000000000000000000000000000000000000000de80fb430f6b29b4")
	data[common.HexToHash("0xe85d96778ab876912e125b3cd2a76698c9cb08ccf3df6966840bfb5820570c98")] = common.HexToHash("0x5460da56332c8383f231a0cb60b4e87217f80e6c587399aab70aae21cee4acda")
	data[common.HexToHash("0x662773fe4e9954c4a7094826f7259558e3dee894180315d66ecd5bf290807908")] = common.HexToHash("0x00000000000000000000000000000000000000000000000035e9e0c974ff2389")
	data[common.HexToHash("0x7004b38e75ae16a877f6d6a44c50f4a9a96feec59b8d5147ad63a70d70702317")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xfa7de321ad7727b5a1faa69faf306a62e8b5e0392012d1c6e9175e48d69367e3")] = common.HexToHash("0xad4786bef37e197f741e6a3f38b232693986582167b9869b128d15923b14c056")
	data[common.HexToHash("0x5dbb635b35fc26891d2746712e34d99f12d24a2ab97ab2506a20886e440d4430")] = common.HexToHash("0x2c3f7ed2ea7574f68c6f4d4f90f22e32f159ab219c1c0a9e26776f8799c85e2b")
	data[common.HexToHash("0xb9666c69cad1b4c1a8cfdea17150c06b9be9482f15e73ccaf8b68baf700da876")] = common.HexToHash("0x000000000000000000000000000000000000000000000000de80fb430f6b29b4")
	data[common.HexToHash("0x535ed09cde405d48f2a4d354215438c383ad74fff8235faacefaa29b12492036")] = common.HexToHash("0x00000000000000000000000000000000a8093207884277d09a525487fa6e3d2e")
	data[common.HexToHash("0x3745d821a9cbde81d60a2b307aaf82d8979f0530c8562c982d2e925008c7ff5e")] = common.HexToHash("0x67bd07f01b1464beac4cb40786ec53b2701f2ae65d93cb789f38e6669a550978")
	data[common.HexToHash("0xac07e5969dc3e0d199537f8f1950d2cba006fd59e531a1a3d87ad7719b13543d")] = common.HexToHash("0x00000000000000000000000000000000b47994b7fc3b7da1107d1eaf3f9fa187")
	data[common.HexToHash("0xd40889565be886302a390f1860fc0beadd5fb5ab60ed9dec7a93f5bcec1a8f32")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x276cd811cd2f2a32d2d7e37c59e3abb19b1ccfe52aae363ea5bb508629ab62c4")] = common.HexToHash("0x6bc0305484442622ca05a49a238bb3e7a36adb2dec020feaceca5b983d8a43fb")
	data[common.HexToHash("0xe143a68be768246f24ad75a717acca72ef99423c4f589ea909a8ec453ba6cadb")] = common.HexToHash("0x000000000000000000000000000000000000000000000000056b815c256ec671")
	data[common.HexToHash("0x31e137fc1914f06b033643f656e6afc47f7683da78d26476b302773eb83e7400")] = common.HexToHash("0x00000000000000000000000000000000660ba36ec7e5f4b1d12c209b0b238bc8")
	data[common.HexToHash("0x0b661fcad4c0846e3ce383f850f263b279652e74f5a462f3f88039aa0fc00f4c")] = common.HexToHash("0x0000000000000000000000000000000068a34ce81daa4602660ba36ec7e5f4b1")
	data[common.HexToHash("0xfa7de321ad7727b5a1faa69faf306a62e8b5e0392012d1c6e9175e48d69367e2")] = common.HexToHash("0xbeeed06ba2f4e2f49dff67339f77b87bf0dd885fd500f61378f9d861c5c97de0")
	data[common.HexToHash("0xe85d96778ab876912e125b3cd2a76698c9cb08ccf3df6966840bfb5820570c9a")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x1765891ac8c202799c0eebaa10f38d0893cc816ae3a64a96a57fed48e4f168bf")] = common.HexToHash("0x000000000000000000000000000000000000000000000000a8093207884277d0")
	data[common.HexToHash("0xda0f5d16ebbad5ec6deb9b44e24df3a369aceaded22ef1471dba34965a53c187")] = common.HexToHash("0xde80fb430f6b29b41951f7db1b198a058e44ecf9dec030e9a0aacacb526a0492")
	data[common.HexToHash("0x044bd137f45c8194d6c50ab016755042295e71fbf721ae16e94367036fbd1d33")] = common.HexToHash("0x0000000000000000000000000000000000000000000000009a525487fa6e3d2e")
	data[common.HexToHash("0x14927649eca7194f0de3c56c2a55998222b844598dc4b0368ce5d2641a418fa7")] = common.HexToHash("0x00000000000000000000000000000000000000000000000068a34ce81daa4602")
	data[common.HexToHash("0xbce09c3c4d629a2120c887750c61b3d551c12620057ba248bd358118d014ec5c")] = common.HexToHash("0x000000000000000000000000000000001fe4570905397f012e812dae96347b61")
	data[common.HexToHash("0x31e137fc1914f06b033643f656e6afc47f7683da78d26476b302773eb83e7401")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x0b661fcad4c0846e3ce383f850f263b279652e74f5a462f3f88039aa0fc00f4b")] = common.HexToHash("0x5704236b411e5a5654581fe9027de75c8af0aa6ee9b7fcc5c53f3953790ba4a3")
	data[common.HexToHash("0x3745d821a9cbde81d60a2b307aaf82d8979f0530c8562c982d2e925008c7ff5f")] = common.HexToHash("0x00000000000000000000000000000000a2d9f0e64e15cb15056b815c256ec671")
	data[common.HexToHash("0xb1fce4b2cd010a564ec99b9ea049bfd6d7f61ebb1a08189bb9d06cf26cb58be2")] = common.HexToHash("0x00000000000000000000000000000000beeed06ba2f4e2f4fdbafc721caef873")
	data[common.HexToHash("0x5579286e2e0e1d19c92d44651b452c2428ba074e83d2c08422f7b39d44afc795")] = common.HexToHash("0x00000000000000000000000000000000000000000000000006a405b7ae505fdd")
	data[common.HexToHash("0xac07e5969dc3e0d199537f8f1950d2cba006fd59e531a1a3d87ad7719b13543e")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x082bf5a6b23846ff8a0630619855da5ebf958dc6cca2229a87626062266ef7d9")] = common.HexToHash("0x000000000000000000000000000000000000000000000000b47994b7fc3b7da1")
	data[common.HexToHash("0xda0f5d16ebbad5ec6deb9b44e24df3a369aceaded22ef1471dba34965a53c189")] = common.HexToHash("0x000000000000000000000000000000008426b609853d78666bc0305484442622")
	data[common.HexToHash("0xa728b64b8eeeae868982d0e84701b1e766931dfc43b5eff0e6f04b67eaf57228")] = common.HexToHash("0x8426b609853d7866966dfd954189304c9c2cb62d931f40f43677769b47a18ae1")
	data[common.HexToHash("0xac07e5969dc3e0d199537f8f1950d2cba006fd59e531a1a3d87ad7719b13543c")] = common.HexToHash("0x30d1af6cd9ecde2034820ef769702cc0e3a09b3369928821929acd4ee89db192")
	data[common.HexToHash("0x80e3e8531be41be800b13494c0e1510ff42e3a44fffea06614fb3cf3ca0fc301")] = common.HexToHash("0x0000000000000000000000000000000000000000000000001fe4570905397f01")
	data[common.HexToHash("0x68829bc93a4ce971269795ead3c2c74ea4a3acc0a4ca5b282d580345f99b0d6b")] = common.HexToHash("0xd3980a794e3e21a15748dfd7a19957e69bfd908da96ed831b376a65906233989")
	data[common.HexToHash("0xfa7de321ad7727b5a1faa69faf306a62e8b5e0392012d1c6e9175e48d69367e4")] = common.HexToHash("0x000000000000000000000000000000006d790c61ae7b9137a2d9f0e64e15cb15")
	data[common.HexToHash("0x42a112c16e83e4d560e20f985532e58c5928213dc52a844e7b4e2f56765a993d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000d12c209b0b238bc8")
	data[common.HexToHash("0x535ed09cde405d48f2a4d354215438c383ad74fff8235faacefaa29b12492035")] = common.HexToHash("0x7bb55981601e38644f2aaab96ff1b3f95a0400cec0ec803c25975bdcef8ca86a")
	data[common.HexToHash("0xc4146cc6bb2050ddb9b5fb02702dbe20ca54cc475596038ea5647df081fb2504")] = common.HexToHash("0x6d790c61ae7b9137c4b088266ebbaaca76c55383e53986871e2aeb031915af57")
	data[common.HexToHash("0x6b25bd5a017de509c42b58fd2614e1ce86631ab34704807d24286ab9290b1f2e")] = common.HexToHash("0x000000000000000000000000000000000000000000000000beeed06ba2f4e2f4")
	data[common.HexToHash("0x1611f897f439025db1080bbc093adbff445b359cdc767a1214cdd8a0415d017d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000107d1eaf3f9fa187")
	data[common.HexToHash("0xb1fce4b2cd010a564ec99b9ea049bfd6d7f61ebb1a08189bb9d06cf26cb58be0")] = common.HexToHash("0xa2d9f0e64e15cb1593dca9abed0188989051f8cd24183df007278a3aac13c520")
	data[common.HexToHash("0xa728b64b8eeeae868982d0e84701b1e766931dfc43b5eff0e6f04b67eaf5722b")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xe12c3f464c5480c925966d60a1477d3e21cedd0584b89d1df88271ba5e0059c4")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xfa7de321ad7727b5a1faa69faf306a62e8b5e0392012d1c6e9175e48d69367e5")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x3745d821a9cbde81d60a2b307aaf82d8979f0530c8562c982d2e925008c7ff60")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xc4146cc6bb2050ddb9b5fb02702dbe20ca54cc475596038ea5647df081fb2505")] = common.HexToHash("0x91fda3681ea86a3f57c72dbe93fa2324fbc997338ed71b3188f3817d03078868")
	data[common.HexToHash("0x7ad41ffd7cf9cae4b11197184be0de767b38d8b4fb3cdf78dee8a3d66766b9b5")] = common.HexToHash("0x0000000000000000000000000000000000000000000000006d790c61ae7b9137")
	data[common.HexToHash("0x092be04c8b4e0cbb7a8f4ba4e42054e51073bff0dd48e6d14adafc04cb44350d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000013e2e93950c015f")
	data[common.HexToHash("0xc4146cc6bb2050ddb9b5fb02702dbe20ca54cc475596038ea5647df081fb2506")] = common.HexToHash("0x000000000000000000000000000000009a525487fa6e3d2ebeeed06ba2f4e2f4")
	data[common.HexToHash("0xe7be15a30366ee3b1772ea2ad4fca48ca7e6a9bbf6c27cc7d7b646320165824a")] = common.HexToHash("0x00000000000000000000000000000000107d1eaf3f9fa1876d790c61ae7b9137")
	data[common.HexToHash("0xe7be15a30366ee3b1772ea2ad4fca48ca7e6a9bbf6c27cc7d7b646320165824b")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xac07e5969dc3e0d199537f8f1950d2cba006fd59e531a1a3d87ad7719b13543b")] = common.HexToHash("0xa8093207884277d0ad6adc7adca94ef669dcf62921f2ce377439783e018cb42c")
	data[common.HexToHash("0xe85d96778ab876912e125b3cd2a76698c9cb08ccf3df6966840bfb5820570c97")] = common.HexToHash("0x06a405b7ae505fddd0bcd41e722abc69a3117700df8ff0df5b1f835d899a9c37")
	data[common.HexToHash("0x31e137fc1914f06b033643f656e6afc47f7683da78d26476b302773eb83e73fe")] = common.HexToHash("0x1fe4570905397f0174df5209b00accee8b9936bf55edeba6fe2239823215a6f4")
	data[common.HexToHash("0x4448f20d53877e2984fdb94979071ba466d32cb980494078a162baf1189165cc")] = common.HexToHash("0x0000000000000000000000000000000000000000000000006bc0305484442622")
	data[common.HexToHash("0xbce09c3c4d629a2120c887750c61b3d551c12620057ba248bd358118d014ec5a")] = common.HexToHash("0xd12c209b0b238bc81d245282efab942a56118dd25738d9b296f3b904435e8562")
	data[common.HexToHash("0xc1a52b552b96dddf13a62a4f8cdb33bb0818a3b8ebb4d8e7d4ed937da49dcff4")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x3745d821a9cbde81d60a2b307aaf82d8979f0530c8562c982d2e925008c7ff5d")] = common.HexToHash("0xfdbafc721caef8739546e63e455c703ef76907e6457632693eb02fca23268248")
	data[common.HexToHash("0xb1fce4b2cd010a564ec99b9ea049bfd6d7f61ebb1a08189bb9d06cf26cb58be3")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xc4146cc6bb2050ddb9b5fb02702dbe20ca54cc475596038ea5647df081fb2507")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xe12c3f464c5480c925966d60a1477d3e21cedd0584b89d1df88271ba5e0059c1")] = common.HexToHash("0x2e812dae96347b61aa7d4712b996b438422529d5c9416a5be6f3f94ecf2eda7a")
	data[common.HexToHash("0x7004b38e75ae16a877f6d6a44c50f4a9a96feec59b8d5147ad63a70d70702314")] = common.HexToHash("0x660ba36ec7e5f4b1c3086675f67343f08e145da56db64459a96ae39413c266a9")
	data[common.HexToHash("0x5dbb635b35fc26891d2746712e34d99f12d24a2ab97ab2506a20886e440d4431")] = common.HexToHash("0x000000000000000000000000000000006bc0305484442622b47994b7fc3b7da1")
	data[common.HexToHash("0xbce09c3c4d629a2120c887750c61b3d551c12620057ba248bd358118d014ec5d")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x276cd811cd2f2a32d2d7e37c59e3abb19b1ccfe52aae363ea5bb508629ab62c6")] = common.HexToHash("0x00000000000000000000000000000000de80fb430f6b29b435e9e0c974ff2389")
	data[common.HexToHash("0xda0f5d16ebbad5ec6deb9b44e24df3a369aceaded22ef1471dba34965a53c18a")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")] = common.HexToHash("0x0000000000000000000000000000000000000000000000008426b609853d7866")
	data[common.HexToHash("0x535ed09cde405d48f2a4d354215438c383ad74fff8235faacefaa29b12492034")] = common.HexToHash("0x107d1eaf3f9fa187b66f43bbd06dd4435554b7c16ef91370e2778a1ac3006a6c")
	data[common.HexToHash("0x276cd811cd2f2a32d2d7e37c59e3abb19b1ccfe52aae363ea5bb508629ab62c7")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x535ed09cde405d48f2a4d354215438c383ad74fff8235faacefaa29b12492037")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xcd75105323881aa206d085b436fb2793c3ca4e76e63f794cde226b231f54a2dc")] = common.HexToHash("0x0000000000000000000000000000000000000000000000008426b609853d7866")
	data[common.HexToHash("0xe12c3f464c5480c925966d60a1477d3e21cedd0584b89d1df88271ba5e0059c3")] = common.HexToHash("0x00000000000000000000000000000000d12c209b0b238bc806a405b7ae505fdd")
	data[common.HexToHash("0xe12c3f464c5480c925966d60a1477d3e21cedd0584b89d1df88271ba5e0059c2")] = common.HexToHash("0x5bbae23d0c5b2a9903c6abc3b81f7606b4db74c84fb4885804b9152772432035")
	data[common.HexToHash("0x7004b38e75ae16a877f6d6a44c50f4a9a96feec59b8d5147ad63a70d70702315")] = common.HexToHash("0x39d6e2126ae9cf947702bb39b8bc037c62d1ab5d1843fa047194f5c4e4ee8535")
	data[common.HexToHash("0xc1a52b552b96dddf13a62a4f8cdb33bb0818a3b8ebb4d8e7d4ed937da49dcff1")] = common.HexToHash("0x68a34ce81daa46026107537df870fba487d1d291e17f6ffc0c1a18a3d9e26f18")
	data[common.HexToHash("0xc1a52b552b96dddf13a62a4f8cdb33bb0818a3b8ebb4d8e7d4ed937da49dcff2")] = common.HexToHash("0xf5c5b23d5f8e08a067f76b67e816a2b815d6223c6daf40d2a428d8b1ca9c4cf1")
	data[common.HexToHash("0xd40889565be886302a390f1860fc0beadd5fb5ab60ed9dec7a93f5bcec1a8f31")] = common.HexToHash("0x0000000000000000000000000000000035e9e0c974ff2389a8093207884277d0")
	data[common.HexToHash("0x184cd3861bd6ddd319500ca6bd8c2ed632bfc7786444c2b16a0dad73ea4e4b0c")] = common.HexToHash("0x000000000000000000000000000000000000000000000000660ba36ec7e5f4b1")
	data[common.HexToHash("0x1623a934daba0d666b4573d50a1fbe62b95639af96898a07387067534e91c156")] = common.HexToHash("0x1fb61d2e56d67af3ff033648c4cfbeb858c6b52178ec6d37ac7a0b91ca815aec")
	data[common.HexToHash("0xb1fce4b2cd010a564ec99b9ea049bfd6d7f61ebb1a08189bb9d06cf26cb58be1")] = common.HexToHash("0xa74b63a1b3d95ae61d3bfea4cc5cdfa741804a6cc760ff8e5d3990524faa24de")
	data[common.HexToHash("0xbce09c3c4d629a2120c887750c61b3d551c12620057ba248bd358118d014ec5b")] = common.HexToHash("0x843bf715cdc8922ccf1f92c036179f7e027cfc91d3521a15ec820f8b74db2930")
	data[common.HexToHash("0xc1a52b552b96dddf13a62a4f8cdb33bb0818a3b8ebb4d8e7d4ed937da49dcff3")] = common.HexToHash("0x000000000000000000000000000000001fb61d2e56d67af3013e2e93950c015f")
	data[common.HexToHash("0x1623a934daba0d666b4573d50a1fbe62b95639af96898a07387067534e91c157")] = common.HexToHash("0xdecc21a0f99f9eaa691b88ab220aec23c0d85127c4200120bd21e4bb822eeedc")
	data[common.HexToHash("0x5dbb635b35fc26891d2746712e34d99f12d24a2ab97ab2506a20886e440d442f")] = common.HexToHash("0x35e9e0c974ff2389230e7a1e101c1289a961d397a78940d3722431bf32a7637c")
	data[common.HexToHash("0x31e137fc1914f06b033643f656e6afc47f7683da78d26476b302773eb83e73ff")] = common.HexToHash("0x6780d898d5d917f8d90c3c9eebf1a79b9375048869d91dc54632b62c7285e6a2")
	data[common.HexToHash("0x7004b38e75ae16a877f6d6a44c50f4a9a96feec59b8d5147ad63a70d70702316")] = common.HexToHash("0x00000000000000000000000000000000013e2e93950c015f1fe4570905397f01")
	data[common.HexToHash("0x68829bc93a4ce971269795ead3c2c74ea4a3acc0a4ca5b282d580345f99b0d6d")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xf42666ee7c99fff5d84b51864d71dc69d8f19f37169ba267dbdfe1f3f539212d")] = common.HexToHash("0x000000000000000000000000000000000000000000000000a2d9f0e64e15cb15")
	data[common.HexToHash("0xd40889565be886302a390f1860fc0beadd5fb5ab60ed9dec7a93f5bcec1a8f2f")] = common.HexToHash("0xb47994b7fc3b7da10ed4fac90a06e5f0d3a0b2b2c8e83f62b874e796f56fff83")
	data[common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")] = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000015")
	data[common.HexToHash("0xe85d96778ab876912e125b3cd2a76698c9cb08ccf3df6966840bfb5820570c99")] = common.HexToHash("0x000000000000000000000000000000002e812dae96347b610000000000000000")
	data[common.HexToHash("0x0b661fcad4c0846e3ce383f850f263b279652e74f5a462f3f88039aa0fc00f4d")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x68829bc93a4ce971269795ead3c2c74ea4a3acc0a4ca5b282d580345f99b0d6c")] = common.HexToHash("0x00000000000000000000000000000000fdbafc721caef8731fb61d2e56d67af3")
	data[common.HexToHash("0xe7be15a30366ee3b1772ea2ad4fca48ca7e6a9bbf6c27cc7d7b6463201658248")] = common.HexToHash("0x9a525487fa6e3d2e2019fbdc5e0c8ec449476f696f8d9e7fd64a7b3a416ce517")
	data[common.HexToHash("0xe7be15a30366ee3b1772ea2ad4fca48ca7e6a9bbf6c27cc7d7b6463201658249")] = common.HexToHash("0x8422b55a431a672a9413dd9a7a47dc5e50d6d3dd397fa5c013c7f31c200b94dd")
	data[common.HexToHash("0xd40889565be886302a390f1860fc0beadd5fb5ab60ed9dec7a93f5bcec1a8f30")] = common.HexToHash("0x04d63214afe9ea5ecd89b6b4f0eb8080bfbac717dc82dbfd1db1e988eaacb6fd")
	data[common.HexToHash("0x5dbb635b35fc26891d2746712e34d99f12d24a2ab97ab2506a20886e440d4432")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0x276cd811cd2f2a32d2d7e37c59e3abb19b1ccfe52aae363ea5bb508629ab62c5")] = common.HexToHash("0xfaf168491c366cbf9b31f5638b72c31c3afd92ab6936316972124a6811d88ed1")
	data[common.HexToHash("0x1623a934daba0d666b4573d50a1fbe62b95639af96898a07387067534e91c159")] = common.HexToHash("0x00000000000000000000000085491884a2c455d46444bb4fbb74dc13680acc84")
	data[common.HexToHash("0xa728b64b8eeeae868982d0e84701b1e766931dfc43b5eff0e6f04b67eaf57229")] = common.HexToHash("0x3d0d6d49cbcb904e4a42ac71f9c359ddfdbefb646d49443e0f920989204bdb4a")
	data[common.HexToHash("0xeadb89f8c5b3e0623e9aa1de9251030ef8befabb89aaf621e669c4592599d977")] = common.HexToHash("0x000000000000000000000000000000000000000000000000fdbafc721caef873")
	data[common.HexToHash("0x56f53e72ffc8b5a79cc4ffbfafd8428bc7a86f41ee264cde09e9310e4b942ba4")] = common.HexToHash("0x0000000000000000000000000000000000000000000000001fb61d2e56d67af3")
	data[common.HexToHash("0x68829bc93a4ce971269795ead3c2c74ea4a3acc0a4ca5b282d580345f99b0d6a")] = common.HexToHash("0x056b815c256ec671b6b6c2bb1d36987d0b0a028534ff8899d62dc7cbdf25e4bf")
	data[common.HexToHash("0x2a7ffd36bf1f4a1e249289e2cf413dbe33defeadcbc100644b2e44adce2b2121")] = common.HexToHash("0x0000000000000000000000000000000000000000000000002e812dae96347b61")

	return GenesisAccount{
		Balance: big.NewInt(0),
		Nonce:   0,
		Storage: data,
		Code:    hexutil.MustDecode("0x6080604052600436106100f9576000357c01000000000000000000000000000000000000000000000000000000009004806373b150981161009c578063a737b18611610076578063a737b18614610b5a578063c1292cc314610b6f578063e91431f714610b84578063ffdd5cf114610b99576100f9565b806373b1509814610ada57806378583f2314610aef5780639382255714610b45576100f9565b8063251c22d1116100d8578063251c22d1146109c85780632f92673214610a6e57806331deb7e114610a9357806372b507e714610aa8576100f9565b8062b54ea6146108e157806316e7f1711461090857806319fe9a3b14610950575b34801561010557600080fd5b503360009081526004602052604090205460c060020a02600160c060020a031981161561039657600160c060020a03198116600090815260036020526040902060060154151561027a57600160c060020a03198082166000908152600360205260408120600160069091018190556002805490910190555468010000000000000000900460c060020a0216156101de576000805468010000000000000000900460c060020a908102600160c060020a0319168252600360205260409091206002018054600160c060020a03168284049092029190911790555b60008054600160c060020a031983168252600360205260408220600201805460c060020a680100000000000000009384900481028190047001000000000000000000000000000000000277ffffffffffffffff000000000000000000000000000000001990921691909117600160c060020a031690915582549084049091026fffffffffffffffff00000000000000001990911617905561031b565b600160c060020a03198116600090815260036020526040812060050154111561031b57600160c060020a0319811660009081526003602052604090206005015443036103208111156102ec57600160c060020a0319821660009081526003602052604090206001600690910155610319565b600160c060020a031982166000908152600360205260409020600681018054830190556007018054820190555b505b600160c060020a0319811660009081526003602052604090204360058201556002015461036190700100000000000000000000000000000000900460c060020a02610bf7565b600160c060020a031981166000908152600360205260409020600201546103919060c060020a9081900402610bf7565b6108de565b3360009081526005602052604081205411156108de57336000908152600560205260409020805460001981019190829081106103ce57fe5b6000918252602080832060048304015460039283166008026101000a900460c060020a02600160c060020a03198116808552929091526040909220549193501580159061041a57508015155b151561042557600080fd5b61042e83610c64565b6104366114de565b61043e6114f9565b828252600160c060020a031985166000908152600360209081526040822060010154818501529082906080908590600b600019f1151561047d57600080fd5b8051600160a060020a0381166000908152600460209081526040808320805467ffffffffffffffff19169055600160c060020a0319898116845260039092529091206002015460c060020a8082029268010000000000000000909204029082161561052957600160c060020a03198216600090815260036020526040902060020180546fffffffffffffffff000000000000000019166801000000000000000060c060020a8404021790555b600160c060020a031981161561057157600160c060020a031981166000908152600360205260409020600201805467ffffffffffffffff191660c060020a840417905561058b565b6000805467ffffffffffffffff191660c060020a84041790555b600080600360008b600160c060020a031916600160c060020a031916815260200190815260200160002060040154119050610160604051908101604052806000600102815260200160006001028152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a03191681526020016000600160a060020a031681526020016000815260200160008152602001600081526020016000815250600360008b600160c060020a031916600160c060020a0319168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548167ffffffffffffffff021916908360c060020a9004021790555060608201518160020160086101000a81548167ffffffffffffffff021916908360c060020a9004021790555060808201518160020160106101000a81548167ffffffffffffffff021916908360c060020a9004021790555060a08201518160020160186101000a81548167ffffffffffffffff021916908360c060020a9004021790555060c08201518160030160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e08201518160040155610100820151816005015561012082015181600601556101408201518160070155905050600060c060020a026005600033600160a060020a0316600160a060020a03168152602001908152602001600020898154811015156107e357fe5b90600052602060002090600491828204019190066008026101000a81548167ffffffffffffffff021916908360c060020a90040217905550876005600033600160a060020a0316600160a060020a031681526020019081526020016000208161084c9190611518565b506001805460001901905560408051600160c060020a03198b16815233602082015281517f86d1ab9dbf33cb06567fbeb4b47a6a365cf66f632380589591255187f5ca09cd929181900390910190a180156108d557604051339060009069021e0c0013070adc00009082818181858883f193505050501580156108d3573d6000803e3d6000fd5b505b50505050505050505b50005b3480156108ed57600080fd5b506108f6610df5565b60408051918252519081900360200190f35b34801561091457600080fd5b5061093c6004803603602081101561092b57600080fd5b5035600160c060020a031916610dfb565b604080519115158252519081900360200190f35b34801561095c57600080fd5b506109896004803603604081101561097357600080fd5b50600160a060020a038135169060200135610e19565b604051828152602081018260a080838360005b838110156109b457818101518382015260200161099c565b505050509050019250505060405180910390f35b3480156109d457600080fd5b506109fc600480360360208110156109eb57600080fd5b5035600160c060020a031916610f24565b604080519b8c5260208c019a909a52600160c060020a03199889168b8b015296881660608b015294871660808a01529290951660a0880152600160a060020a031660c087015260e086019390935261010085019290925261012084019190915261014083015251908190036101600190f35b610a9160048036036040811015610a8457600080fd5b5080359060200135610fa7565b005b348015610a9f57600080fd5b506108f6610fb6565b610a9160048036036060811015610abe57600080fd5b5080359060208101359060400135600160a060020a0316610fc4565b348015610ae657600080fd5b506108f6611420565b348015610afb57600080fd5b50610b2860048036036040811015610b1257600080fd5b50600160a060020a038135169060200135611426565b60408051600160c060020a03199092168252519081900360200190f35b348015610b5157600080fd5b506108f661146e565b348015610b6657600080fd5b506108f661147a565b348015610b7b57600080fd5b50610b28611480565b348015610b9057600080fd5b50610b2861148c565b348015610ba557600080fd5b50610bcc60048036036020811015610bbc57600080fd5b5035600160a060020a03166114a4565b6040805195865260208601949094528484019290925260608401526080830152519081900360a00190f35b600160c060020a0319811615801590610c285750600160c060020a0319811660009081526003602052604090205415155b15610c6157600160c060020a0319811660009081526003602052604090206005015461032043919091031115610c6157610c6181610c64565b50565b600160c060020a031981166000908152600360205260408120600601541115610c615760028054600019018155600160c060020a0319808316600090815260036020526040812060068101919091559091015460c060020a7001000000000000000000000000000000008204810292918190040290821615610d3f57600160c060020a031982811660009081526003602052604080822060029081018054600160c060020a031660c060020a808804021790559286168252902001805477ffffffffffffffff00000000000000000000000000000000191690555b600160c060020a0319811615610dc357600160c060020a03198181166000908152600360205260408082206002908101805477ffffffffffffffff00000000000000000000000000000000191670010000000000000000000000000000000060c060020a89040217905592861682529020018054600160c060020a03169055610df0565b600080546fffffffffffffffff000000000000000019166801000000000000000060c060020a8504021790555b505050565b60025481565b600160c060020a031916600090815260036020526040902054151590565b6000610e2361154c565b600160a060020a038416600090815260056020908152604091829020805483518184028101840190945280845260609392830182828015610eb357602002820191906000526020600020906000905b82829054906101000a900460c060020a02600160c060020a03191681526020019060080190602082600701049283019260010382029150808411610e725790505b5050835196509293506000925050505b600581108015610ed4575083858201105b15610f1b5781858201815181101515610ee957fe5b60209081029091010151838260058110610eff57fe5b600160c060020a03199092166020929092020152600101610ec3565b50509250929050565b6003602081905260009182526040909120805460018201546002830154938301546004840154600585015460068601546007909601549496939560c060020a8086029668010000000000000000870482029670010000000000000000000000000000000081048302969083900490920294600160a060020a03909216939192908b565b610fb2828233610fc4565b5050565b69021e19e0c9bab240000081565b82600160c060020a0319811615801590610fdd57508215155b80156110005750600160c060020a03198116600090815260036020526040902054155b8015611015575069021e19e0c9bab240000034145b151561102057600080fd5b6110286114de565b6110306114f9565b8582526020808301869052816080846000600b600019f1151561105257600080fd5b8051600160a060020a038116151561106957600080fd5b836004600083600160a060020a0316600160a060020a0316815260200190815260200160002060006101000a81548167ffffffffffffffff021916908360c060020a90040217905550610160604051908101604052808881526020018781526020016000809054906101000a900460c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a0319168152602001600060c060020a02600160c060020a031916815260200186600160a060020a03168152602001438152602001600081526020016000815260200160008152506003600086600160c060020a031916600160c060020a0319168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548167ffffffffffffffff021916908360c060020a9004021790555060608201518160020160086101000a81548167ffffffffffffffff021916908360c060020a9004021790555060808201518160020160106101000a81548167ffffffffffffffff021916908360c060020a9004021790555060a08201518160020160186101000a81548167ffffffffffffffff021916908360c060020a9004021790555060c08201518160030160006101000a815481600160a060020a030219169083600160a060020a0316021790555060e08201518160040155610100820151816005015561012082015181600601556101408201518160070155905050600060c060020a02600160c060020a0319166000809054906101000a900460c060020a02600160c060020a0319161415156113255760008054600160c060020a031960c060020a91820216825260036020526040909120600201805491860468010000000000000000026fffffffffffffffff0000000000000000199092169190911790555b6000805467ffffffffffffffff191660c060020a86049081178255600160a060020a0387811683526005602090815260408085208054600181810183559187529286206004840401805467ffffffffffffffff60039095166008026101000a9485021916939095029290921790935580548101905590519083169190670de0b6b3a76400009082818181858883f193505050501580156113c9573d6000803e3d6000fd5b5060408051600160c060020a031986168152600160a060020a038716602082015281517ff19f694d42048723a415f5eed7c402ce2c2e5dc0c41580c3f80e220db85ac389929181900390910190a150505050505050565b60015481565b60056020528160005260406000208181548110151561144157fe5b9060005260206000209060049182820401919006600802915091509054906101000a900460c060020a0281565b670de0b6b3a764000081565b61032081565b60005460c060020a0281565b60005468010000000000000000900460c060020a0281565b600154600254600160a060020a0392909216600090815260056020526040902054670de0b6b3a764000030310493600a4360300204939190565b60408051808201825290600290829080388339509192915050565b6020604051908101604052806001906020820280388339509192915050565b815481835581811115610df0576003016004900481600301600490048360005260206000209182019101610df0919061156b565b60a0604051908101604052806005906020820280388339509192915050565b61158991905b808211156115855760008155600101611571565b5090565b9056fea165627a7a72305820c044eb3e1caeb73630becc79ac14f023ad04a34dcf52035fa5bc472236874b2b0029"),
	}
}
