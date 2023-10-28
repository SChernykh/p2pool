## Merge mining tx_extra tag format

- TX_EXTRA_MERGE_MINING_TAG (1 byte)
	- A single byte of value `3`
- Size (in bytes) of the following fields (1 byte)
	- Technically a Varint, but it's always a single byte in practice
- Merkle tree parameters (1 or multiple bytes - 64-bit value encoded as varint)
- Merkle root hash (32 bytes)

## Merkle tree parameters

A 64-bit value encoding the total number of aux chains hashed into the Merkle root hash, and an aux nonce that defines the order of aux chains when building the Merkle tree.

Bit|Description
-|-
0...2|`N-1` - number of bits used to store `n_aux_chains` (value 0 means 1 bit, ..., value 7 means 8 bits)
3...`N`+2|`n_aux_chains-1` (value 0 means 1 chain, and so on)
`N`+3...`N`+34|`aux_nonce` (32-bit value)
`N`+35...63|reserved (current implementations must set these bits to all 0 when writing and ignore these bits when reading)

`N` must be the smallest number of bits enough to represent `n_aux_chains-1`

Reference code: `PoolBlock::encode_merkle_tree_data` and `PoolBlock::decode_merkle_tree_data` in `pool_block.h`

## Merkle tree construction's first step (Monero-specific)

If `n_aux_chains` is not a power of 2, their hashes are combined starting from the end of the list of hashes until there are a power of 2 hashes left. Then they're processed normally.

Example 1: 6 hashes `H0, H1, H2, H3, H4, H5` will be transformed into 4 hashes `H0, H1, H(H2|H3), H(H4|H5)` where `H` is the hash function and `|` is concatenation.

Example 2: 5 hashes `H0, H1, H2, H3, H4` will be transformed into 4 hashes `H0, H1, H2, H(H3|H4)`

## The order of hashes in the Merkle tree

Each of the aux chains must provide a 32-byte value `unique_id` that singles it out from any other chain. Genesis block's hash is a good choice for this value, but it can be anything else really.

`unique_id` is used to enforce the order in which aux hashes are added to the Merkle tree. This prevents an attack where miners can mine two versions of the same chain (for example when double spending) without any additional cost.

Forked chains can choose whether to keep their `unique_id` or change it. If they keep it, it will be impossible to merge mine with the chain they forked from beause they will always be assigned the same slot in the Merkle tree.

A deterministic pseudo-random function `SHA256(unique_id|nonce|"m") % N` is applied to determine which slot is used by which chain. `nonce` is brute-forced until all `N` chains are assigned different slots. This limits `N` to no more than 15-16 in practice.

Reference code: `get_aux_slot` and `find_aux_nonce` in `merkle.cpp`

## Proposed RPC API

P2Pool must be able to get mining jobs from merge mined chains and submit PoW solutions to them.

### merge_mining_get_id

Request: an empty JSON

Response: a JSON containing these fields:
Field|Description
-|-
`result`|`OK` or an error message
`id`|A unique 32-byte hex-encoded value that identifies this merge mined chain.

### merge_mining_get_job

Request: a JSON containing these fields:
Field|Description
-|-
`height`|Monero height
`prev_id`|Hash of the previous Monero block
`address`|A wallet address on the merge mined chain
`aux_hash`|Merge mining job that is currently being used

Response: a JSON containing these fields:
Field|Description
-|-
`result`|`OK` or an error message
`aux_blob`|A hex-encoded blob of data. Merge mined chain defines the contents of this blob. It's opaque to P2Pool and will not be changed by it.
`aux_hash`|A 32-byte hex-encoded hash of the `aux_blob`. Merge mined chain defines how exactly this hash is calculated. It's opaque to P2Pool.
`aux_diff`|Mining difficulty (decimal number).

If `aux_hash` is the same as in the request, all other fields will be ignored by P2Pool, so they don't have to be included in the response. Moreover, `{"result":"OK"}` response will be interpreted as a response having the same `aux_hash` as in the request. This enables an efficient polling.

### merge_mining_submit_solution

Request: a JSON containing these fields:
Field|Description
-|-
`aux_blob`|Blob of data returned by `merge_mining_get_job`.
`aux_hash`|A 32-byte hex-encoded hash of the `aux_blob` - the same value that was returned by `merge_mining_get_job`.
`blob`|Monero block template that has enough PoW to satisfy difficulty returned by `merge_mining_get_job`. It also must have a merge mining tag in tx_extra of the coinbase transaction.
`merkle_proof`|A proof that `aux_hash` was included when calculating Merkle root hash from the merge mining tag

Note that `merkle_proof` only contains a vector of 32-byte hashes for `aux_hash` to be combined with. It can be verified by running this pseudo-code and functions from `merkle.cpp` (adapt it to your codebase):

`verify_merkle_proof(aux_hash, merkle_proof, get_aux_slot(unique_id, aux_nonce, n_aux_chains), n_aux_chains, merkle_root_hash)`

`aux_nonce` and `n_aux_chains` can be extracted from the Merkle tree parameters (see above).
`merkle_root_hash` can be extracted from the merge mining tag (see above).
