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

Forked chains can choose whether to keep their `unique_id` or change it. If they keep it, it will not be possible to merge mine with the chain they forked from beause they will always be assigned the same slot in the Merkle tree.

Reference code: `get_aux_slot` and `find_aux_nonce` in `merkle.cpp`
