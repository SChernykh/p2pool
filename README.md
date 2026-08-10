# Kryptokrona P2Pool

Decentralized pool for [Kryptokrona (XKR)](https://github.com/kryptokrona/kryptokrona) mining.

P2Pool combines the advantages of pool and solo mining: you get regular payouts
like on a pool, but you keep full control of your funds and what you mine like
when solo mining. There is no central pool server, no pool wallet, and no pool
operator who can go rogue — pool blocks pay out to miners directly.

> **This is a port of [SChernykh's Monero P2Pool](https://github.com/SChernykh/p2pool)**
> to Kryptokrona. It replaces Monero's RandomX proof-of-work with Kryptokrona's
> **CryptoNight-Turtle** PoW, uses Kryptokrona's address format (SEKR) and coin
> parameters, and talks to `kryptokronad` over JSON-RPC. All credit for the
> original P2Pool design and implementation goes to SChernykh and the Monero
> P2Pool contributors.

## Contents
- [Port status](#port-status)
- [Pool mining vs Solo mining vs P2Pool mining](#pool-mining-vs-solo-mining-vs-p2pool-mining)
- [Features](#features)
- [How payouts work in P2Pool](#how-payouts-work-in-p2pool)
- [Default parameters](#default-parameters)
- [How to run](#how-to-run)
- [Build instructions](#build-instructions)
- [Credits](#credits)

## Port status

| Area | Status |
|-|-|
| Coin parameters (XKR: 5 decimals, prefixes, emission, 90 s main-chain block time) | ✅ |
| CryptoNight-Turtle PoW engine (replaces RandomX) | ✅ |
| Node I/O via `kryptokronad` JSON-RPC polling (ZMQ removed) | ✅ |
| Block / template serialization + mainchain block submission | ✅ (accepted by `kryptokronad`) |
| Wallet / address handling (CryptoNote base58, SEKR prefix) | ✅ |
| Two-node sidechain: connect, consensus ID, handshake, chain-tip sync | ✅ |
| Transactions included in mined blocks | ✅ (verified end-to-end) |
| Multi-wallet PPLNS payout | ⚠️ blocked on the ARM PoW issue below (see notes) |
| **x86_64** Linux / Windows | Target platform — build and run here |
| **ARM64 (incl. Apple Silicon)** | ⚠️ Known bug: the vendored CryptoNight-Turtle produces build-dependent hashes on arm64, so a miner, P2Pool and the daemon do not agree on the PoW. Under investigation — **use x86_64 for now.** |

## Pool mining vs Solo mining vs P2Pool mining

While pool mining is the easiest to set up, it centralizes the network and the
pool admin gets full power over your hashrate and your unpaid funds. Solo mining
is fully independent and best for the network, but payouts are rare. P2Pool
mining has all the advantages of solo mining, but also makes regular payouts
possible.

|Pool type|Payouts|Fee|Centralized?|Control|Setup|
|-|-|-|-|-|-|
|Centralized pool|Regular|0-3%|Yes|The pool admin controls your mined funds and what you mine|Only miner software|
|Solo|Rare|0%|No|100% under your control|Kryptokrona node + optional miner|
|**P2Pool**|Regular|0%|No|100% under your control|Kryptokrona node(s) + P2Pool node(s) + optional miner(s)|

## Features

* **Decentralized:** no central server that can be shut down/blocked. P2Pool uses a separate blockchain (the "sidechain") to merge-mine with Kryptokrona. There is no pool admin.
* **Permissionless:** no one decides who can mine on the pool.
* **Trustless:** there is no pool wallet, funds are never in custody. All pool blocks pay out to miners directly.
* **PPLNS** payout scheme.
* **0% fee**, no minimum payout beyond the per-share reward.
* Node failover and multiple Kryptokrona nodes are supported.

## How payouts work in P2Pool

First you find a pool *share* (a sidechain block). This share stays in the
[PPLNS](https://en.wikipedia.org/wiki/Mining_pool#Pay-per-last-N-shares) window
for up to 2160 pool blocks. The moment P2Pool finds a **Kryptokrona** block and
you have at least one share in the PPLNS window, you get a payout. The Kryptokrona
block reward is split between all miner wallets in the PPLNS window, each getting
a part proportional to the total difficulty of their shares in the window.

**NOTE:** if the pool doesn't have enough hashrate to find Kryptokrona blocks
faster than the PPLNS window on average, not every share results in a payout;
over the long run payouts average out to what you'd get from a regular pool.

## Default parameters

* Sidechain (share) block time: 10 seconds
* PPLNS window: up to 2160 blocks (auto-adjustable to balance payout size/frequency)
* Kryptokrona main-chain block time: 90 seconds
* Proof-of-work: CryptoNight-Turtle (CN-Turtle-Lite v2)

## How to run

You need a synced `kryptokronad` with its JSON-RPC port reachable (default
`11898`), your XKR wallet address, and (for a real pool) at least one other
P2Pool node to peer with — a single isolated P2Pool node will not accept miner
logins until it is connected to the P2Pool network.

```
./p2pool --host 127.0.0.1 --rpc-port 11898 --wallet YOUR_XKR_ADDRESS
```

Then point a CryptoNight-Turtle miner (e.g. XMRig with `--algo cn/turtle`) at the
P2Pool stratum port (default `3333`):

```
xmrig -o 127.0.0.1:3333 -a cn/turtle -u x
```

Useful flags: `--addpeers ip:port,...` (connect to specific P2Pool nodes),
`--stratum ip:port` (stratum bind address), `--data-dir` (where to keep the
cache/log/peer data), `--loglevel N`, `--no-dns`. Run `./p2pool --help` for the
full list. See [How to test on mainnet](#build-instructions) below for a full
two-machine (Linux + Windows) walk-through.

## Build instructions

Only 64-bit builds are supported. **Use x86_64** — see the [Port status](#port-status)
note about arm64.

### Prerequisites
- cmake >= 3.10
- C++ compiler with C++17 support (GCC-8+, Clang-13+, MSVC-2019 tested)

### Ubuntu / Debian (x86_64)
```
sudo apt update && sudo apt install git build-essential cmake libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev libcurl4-openssl-dev libidn2-0-dev
git clone --recursive https://github.com/kryptokrona/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Windows (x86_64)
*NOTE: install the "Desktop Development with C++" module for Visual Studio.*
```
git clone --recursive https://github.com/kryptokrona/p2pool
cd p2pool
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
```
then open the generated `build\p2pool.sln` in Visual Studio and build it there.

### macOS / FreeBSD (development only — see arm64 note)
```
brew update && brew install git cmake libuv zmq libpgm curl     # macOS
git clone --recursive https://github.com/kryptokrona/p2pool
cd p2pool && mkdir build && cd build && cmake .. && make -j$(sysctl -n hw.logicalcpu)
```

## Credits

Kryptokrona P2Pool is a fork of **[Monero P2Pool](https://github.com/SChernykh/p2pool)**
by **SChernykh**, released under the GNU GPL v3. The decentralized pool design,
sidechain/PPLNS implementation, and the vast majority of this code are their
work. This fork adapts it to the Kryptokrona network. If you find P2Pool useful,
please consider supporting the original author's ongoing work on the upstream
project.
