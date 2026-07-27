# Kryptokrona (XKR) v5 block format — reference for the P2Pool port

This is the byte layout P2Pool's `serialize_mainchain_data` / deserialize must
produce for kryptokrona (replacing Monero's flat block format). Validated
against a **live testnet `getblocktemplate` blob** (reserve_size=44):

```
blob (489 bytes, reserved_offset=445):
05007fb97df8...6ef66f4c 0000 b6c39ed306 <32 zero> 00000000 01 <parent coinbase> ... <real coinbase w/ 44-byte reserve at 445> 00
```

## Structure (major_version >= 2, i.e. all modern XKR incl. testnet v5)

Serialization = `serialize(BlockTemplate)` in
`kryptokrona/src/cryptonote_core/cryptonote_serialization.cpp`.

```
OUTER HEADER  (serializeBlockHeader):
  major_version   varint            (5)
  minor_version   varint            (0)
  previousBlockHash  32 bytes       (timestamp & nonce are NOT here for v>=2!)

PARENT BLOCK  (makeParentBlockSerializer(block, hashing=false, headerOnly=false)):
  pb.major_version varint           (0  -- see QUIRK below)
  pb.minor_version varint           (0)
  timestamp        varint           (the real block timestamp)
  pb.previousBlockHash 32 bytes     (all zero)
  nonce            4 bytes binary   (mining varies THIS nonce)
  numberOfTransactions varint       (1)
  baseTransactionBranch   tree_depth(txCount) x 32-byte hashes  (txCount=1 -> 0)
  baseTransaction  (parent coinbase; its `extra` holds a merge-mining tag whose
                    merkle_root = aux hash of the real block header)
  blockchainBranch  (from mm tag depth; depth 0 -> none)

baseTransaction   (the REAL coinbase — multi-output PPLNS payout for P2Pool)
transactionHashes varint count + N x 32-byte hashes
```

## PoW hashing blob (get long hash)  →  feed to CN-Turtle (xkr_cn_turtle_pow)

`getParentBlockHashingBinaryArray(true)` = `makeParentBlockSerializer(block,
hashing=true, headerOnly=true)`:

```
pb.major_version varint
pb.minor_version varint
timestamp        varint
pb.previousBlockHash 32
nonce            4 bytes
merkleRoot       32   = tree_hash_from_branch(baseTransactionBranch,
                        hash(parent baseTransaction), 0)
numberOfTransactions varint
```

## Block ID hash (getBlockHashingBinaryArray)

```
serializeBlockHeader (major, minor, prevHash)
treeHash  32  = tree_hash over [ real baseTransaction hash, ...transactionHashes ]
varint(transactionHashes.size() + 1)
```
Block ID / aux hash = cn_fast_hash (keccak) of that array.

## Coinbase (both parent and real) — CryptoNote, NOT Monero

- version varint, unlock_time varint (real coinbase unlock = height + 20 =
  CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, **not** Monero's 60)
- vin: count=1, tag 0xFF (TXIN_GEN), gen height varint
- vout: count varint, then per output: varint(amount), tag **0x02
  (TXOUT_TO_KEY)**, 32-byte one-time key.  **No view-tag byte** (Monero uses
  0x03 TXOUT_TO_TAGGED_KEY + view tag — kryptokrona does not).
- extra: varint(size) + [0x01 pubkey(32)] [0x02 nonce_tag varint(size) nonce...]
- **No RingCT type byte** at the end (Monero appends 0x00; CryptoNote does not).

## QUIRKS confirmed against the live daemon

1. `pb.major_version == 0` (not 1): kryptokrona core.cpp:1856-1857 assigns
   `parentBlock.majorVersion` twice, the 2nd time to `BLOCK_MINOR_VERSION_0`.
   P2Pool must serialize 0 here or block IDs/PoW won't match consensus.
2. `reserved_offset` (from getblocktemplate) points just past
   `[pubkey tag + 32 + nonce tag + nonce-size counter]` in the REAL coinbase
   extra; the reserve is the tail bytes. P2Pool builds its own coinbase so it
   controls this directly (embed the sidechain merkle root here, or as a
   dedicated extra field).

## CRITICAL: PoW ↔ block linkage (checkProofOfWorkV2, currency.cpp:719)

The PoW long-hash is CN-Turtle over the **parent block** only. On its own that
does NOT commit to the real coinbase/txs. Kryptokrona links them by requiring:

```
mmTag.merkleRoot (in parent coinbase extra)  ==  getAuxiliaryBlockHeaderHash()
```

where `getAuxiliaryBlockHeaderHash = cn_fast_hash(getBlockHashingBinaryArray())`
= keccak( outerHeader ++ treeHash(realCoinbase, txs...) ++ varint(nTx+1) ), and
`blockchainBranch` is empty (depth 0) so `auxBlocksMerkleRoot == that aux hash`.

**Consequence for P2Pool** (per-candidate, every time extra_nonce/outputs/txs change):
1. Build the real block: outer header + real multi-output coinbase + tx hashes.
2. `auxHash = keccak(getBlockHashingBinaryArray())`.
3. Write `auxHash` into the **parent coinbase** mm-tag `merkleRoot` (depth 0).
4. Serialize the parent block; `powBlob = parent-block hashing serialization`.
5. `powHash = xkr_cn_turtle_pow(powBlob)`; compare to difficulty.
6. On a win, submit the full block blob via `submitblock`.

`getblocktemplate` returns the mm-tag merkleRoot as **zero** (daemon appends a
value-initialized tag and never fills it). A dumb pool that only writes
extra_nonce would fail V2 validation; P2Pool builds the whole block so it sets
the merkleRoot correctly. The parent coinbase is otherwise constant:
`version=0, unlock=0, vin=0, vout=0, extra = [0x03, 0x21, depth=0, merkleRoot(32)]`.

The mining mutation (nonce) lives in the **parent block header**; extra_nonce
lives in the **real coinbase** extra (changing it changes the aux hash → must
recompute steps 2-3).

## How to regenerate the reference
```
kryptokronad --data-dir X --no-console --rpc-bind-port 28080 --p2p-bind-port 28081 --add-exclusive-node 127.0.0.1:1
# testnet address from `xkrwallet` (create wallet):
curl -s -XPOST http://127.0.0.1:28080/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"getblocktemplate","params":{"reserve_size":44,"wallet_address":"SEKR..."}}'
```
