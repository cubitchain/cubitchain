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

var MainnetBootnodes = []string{
	"enode://37ad5b2ab5a659ab7372ab9d745dfd5676119a9b3b5c408948222048563a8b497bf1c8ab9ce0a2c88041f75ecfd75cefcc248a8dfe83052c850c1a2ca80d3c28@182.61.168.35:30606", // HK
	"enode://c9f1a568dc14455d1e7d580d6eeeefee493d4896821dff04159f2c7bb645bfe2a9d79e481c1a7b0f28cee66e69b7f73e2a499b49d67267b07eeaab635d86909c@178.128.50.170:30606", // SG
}

var MainnetMasternodes = []string{
	"enode://06a405b7ae505fddd0bcd41e722abc69a3117700df8ff0df5b1f835d899a9c375460da56332c8383f231a0cb60b4e87217f80e6c587399aab70aae21cee4acda",
	"enode://2e812dae96347b61aa7d4712b996b438422529d5c9416a5be6f3f94ecf2eda7a5bbae23d0c5b2a9903c6abc3b81f7606b4db74c84fb4885804b9152772432035",
	"enode://d12c209b0b238bc81d245282efab942a56118dd25738d9b296f3b904435e8562843bf715cdc8922ccf1f92c036179f7e027cfc91d3521a15ec820f8b74db2930",
	"enode://1fe4570905397f0174df5209b00accee8b9936bf55edeba6fe2239823215a6f46780d898d5d917f8d90c3c9eebf1a79b9375048869d91dc54632b62c7285e6a2",
	"enode://660ba36ec7e5f4b1c3086675f67343f08e145da56db64459a96ae39413c266a939d6e2126ae9cf947702bb39b8bc037c62d1ab5d1843fa047194f5c4e4ee8535",
	"enode://013e2e93950c015fd47d13fbe556d8bc9f8175c48c314864a5b7cab6ab62f9fe5704236b411e5a5654581fe9027de75c8af0aa6ee9b7fcc5c53f3953790ba4a3",
	"enode://68a34ce81daa46026107537df870fba487d1d291e17f6ffc0c1a18a3d9e26f18f5c5b23d5f8e08a067f76b67e816a2b815d6223c6daf40d2a428d8b1ca9c4cf1",
	"enode://1fb61d2e56d67af3ff033648c4cfbeb858c6b52178ec6d37ac7a0b91ca815aecdecc21a0f99f9eaa691b88ab220aec23c0d85127c4200120bd21e4bb822eeedc",
	"enode://056b815c256ec671b6b6c2bb1d36987d0b0a028534ff8899d62dc7cbdf25e4bfd3980a794e3e21a15748dfd7a19957e69bfd908da96ed831b376a65906233989",
	"enode://fdbafc721caef8739546e63e455c703ef76907e6457632693eb02fca2326824867bd07f01b1464beac4cb40786ec53b2701f2ae65d93cb789f38e6669a550978",
	"enode://a2d9f0e64e15cb1593dca9abed0188989051f8cd24183df007278a3aac13c520a74b63a1b3d95ae61d3bfea4cc5cdfa741804a6cc760ff8e5d3990524faa24de",
	"enode://beeed06ba2f4e2f49dff67339f77b87bf0dd885fd500f61378f9d861c5c97de0ad4786bef37e197f741e6a3f38b232693986582167b9869b128d15923b14c056",
	"enode://6d790c61ae7b9137c4b088266ebbaaca76c55383e53986871e2aeb031915af5791fda3681ea86a3f57c72dbe93fa2324fbc997338ed71b3188f3817d03078868",
	"enode://9a525487fa6e3d2e2019fbdc5e0c8ec449476f696f8d9e7fd64a7b3a416ce5178422b55a431a672a9413dd9a7a47dc5e50d6d3dd397fa5c013c7f31c200b94dd",
	"enode://107d1eaf3f9fa187b66f43bbd06dd4435554b7c16ef91370e2778a1ac3006a6c7bb55981601e38644f2aaab96ff1b3f95a0400cec0ec803c25975bdcef8ca86a",
	"enode://a8093207884277d0ad6adc7adca94ef669dcf62921f2ce377439783e018cb42c30d1af6cd9ecde2034820ef769702cc0e3a09b3369928821929acd4ee89db192",
	"enode://b47994b7fc3b7da10ed4fac90a06e5f0d3a0b2b2c8e83f62b874e796f56fff8304d63214afe9ea5ecd89b6b4f0eb8080bfbac717dc82dbfd1db1e988eaacb6fd",
	"enode://35e9e0c974ff2389230e7a1e101c1289a961d397a78940d3722431bf32a7637c2c3f7ed2ea7574f68c6f4d4f90f22e32f159ab219c1c0a9e26776f8799c85e2b",
	"enode://6bc0305484442622ca05a49a238bb3e7a36adb2dec020feaceca5b983d8a43fbfaf168491c366cbf9b31f5638b72c31c3afd92ab6936316972124a6811d88ed1",
	"enode://de80fb430f6b29b41951f7db1b198a058e44ecf9dec030e9a0aacacb526a0492ce04367390f08a914c965aa571e937bd0c0b450174ae28e4de45dce7356a10b3",
	"enode://8426b609853d7866966dfd954189304c9c2cb62d931f40f43677769b47a18ae13d0d6d49cbcb904e4a42ac71f9c359ddfdbefb646d49443e0f920989204bdb4a",
}

var TestnetBootnodes = []string{
	"enode://59ca967b2c9c1442e81026f5ffc2b24f4b3787512194a41e4ab14dfac97e75b700988cac80f973641d40cd65f775f41955b93d2e843ebb03555b16dd9bf983d4@127.0.0.1:9646",
}

var TestnetMasternodes = []string{
	"enode://59ca967b2c9c1442e81026f5ffc2b24f4b3787512194a41e4ab14dfac97e75b700988cac80f973641d40cd65f775f41955b93d2e843ebb03555b16dd9bf983d4", // nodekey: a9b50794ab7a9987aa416c455c13aa6cc8c0448c501a3ce8e4840efe47cb5c29
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}