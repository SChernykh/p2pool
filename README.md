# Monero P2Pool

Decentralized pool for Monero mining.

**NOTE** This is a highly experimental and untested software. I did some extensive testing locally, but there's zero guarantee it will work for you! It requires a custom monerod version and a specially configured Monero wallet (for now). No binaries or usage instructions are provided yet. Testing on mainnet has started! No ETA on the official release date, but hopefully before the end of September 2021.

## Pool mining vs Solo mining vs P2Pool mining

Here's the comparison table of the different ways of mining. While pool mining is the easiest to setup, it centralizes Monero network and pool admin gets full power over your hashrate and your unpaid funds. Solo mining is 100% independent and the best for the network. P2Pool mining has all the advantages of solo mining, but also makes regular payouts possible.

|Pool type|Payouts|Fee|Min. payout|Centralized?|Stability|Control|Setup
|-|-|-|-|-|-|-|-|
|Centralized pool|Regular|0-3%|0.001-0.01 XMR|Yes|Less stable due to pool server outages|Pool admin controls your mined funds, what you mine and can execute network attacks|Only miner software is required
|Solo|Rare|0%|0.6 XMR or more|No|As stable as your Monero node|100% under your control|Monero node + optional miner
|**P2Pool**|Regular|0%|less than 0.0005 XMR|No|As stable as your Monero node|100% under your control|Monero node + P2Pool node + miner

## Features

* Decentralized: no central server that can be shutdown/blocked. P2Pool uses a separate blockchain to merge mine with Monero. Pool admin can't go rogue or be pressured to do an attack on the network because there is no pool admin!
* Permissionless: there is no one to decide who can mine on the pool and who can't.
* Trustless: there is no pool wallet, funds are never in custody. All pool blocks pay out to miners immediately.
* PPLNS payout scheme
* **0% fee**
* **0 XMR payout fee**
* **Less than 0.0005 XMR minimal payout**
* Fast block times, down to 1 second
* Uncle blocks are supported to avoid orphans - all your shares will be accounted for!
* Configurable PPLNS window size and block time
* Advanced mempool picking algorithm, it creates blocks with better reward than what monerod solo mining does
* Password protected private pools

## How PPLNS works in P2Pool

First you need to find a pool share. This share will stay in PPLNS window for 2160 pool blocks (6 hours). The moment P2Pool finds a Monero block and you have at least 1 pool share in PPLNS window, you'll get a payout! Monero block reward is split between all miner wallets in PPLNS window. Each miner gets a part of block reward proportional to the total difficulty of his/her shares in PPLNS window.

**NOTE** If P2Pool doesn't have enough hashrate to find Monero blocks faster than every 6 hours on average (~15 MH/s), not all pool shares will result in a payout. But in the long run, your payouts will average out to what you'd get with regular pool mining.

## Default P2Pool parameters

* Block time: 10 seconds
* PPLNS window: 2160 blocks (6 hours)
* Minimum payout = Monero block reward/2160, currently ~0.0004 XMR

## Build instructions

### Ubuntu 20.04

p2pool binary:
```
sudo apt update && sudo apt install git build-essential cmake libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev
git clone https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(nproc)
```

monerod binary compatible with p2pool:
```
sudo apt update && sudo apt install git build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev ccache doxygen graphviz
git clone --recursive https://github.com/SChernykh/monero
cd monero
git checkout p2pool-api-v0.17
git submodule init && git submodule update
make release-static -j$(nproc)
```

## How to test

Mainnet test has started! **PPLNS window = 2160 blocks, block time = 10 seconds**. This guide assumes that you run everything on the same machine. If it's not the case, change `127.0.0.1` to appropriate IP addresses for your setup. It's highly recommended to create a new mainnet wallet for testing because **wallet addresses are public on p2pool**. The purpose of this test is to bring as much hashrate as possible and check if stratum server works fine!

- Grab the latest source code for both p2pool and monerod and build them (see above, also notice that the branch name for monerod changed, you'll need to checkout p2pool-api-v0.17)
- Prepare enough huge pages (each of monerod/p2pool/xmrig needs them): `sudo sysctl vm.nr_hugepages=3072`
- Create a separate restricted user account for testing. p2pool is untested and can have serious bugs/vulnerabilities!
- Get xmrig (linux-static-x64) binary from https://github.com/xmrig/xmrig/releases/latest
- Check that ports 18080 (Monero p2p port) and 37890 (p2pool p2p port) are open in your firewall to ensure better connectivity
- Create a new mainnet wallet
- You have to use the primary wallet address for mining. Subaddresses and integrated addresses are not supported, just like with monerod solo mining
- Open this wallet in CLI: run `./monero-wallet-cli`, enter the wallet file name there and then enter the command `set refresh-type full`. **This step is important!** If you don't do it, you won't see p2pool payouts!
- Run `./monerod --zmq-pub tcp://127.0.0.1:18083` **don't forget --zmq-pub parameter in the command line**
- Double check that it shows **Monero 'Oxygen Orion' (v0.17.2.3-1c9c3b770)** on startup. Wait until it's synchronized.
- Run `./p2pool --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet YOUR_WALLET_ADDRESS --stratum 0.0.0.0:3333 --p2p 0.0.0.0:37890 --addpeers 65.21.227.114:37890`
- Keep both monerod and p2pool running for the whole duration of your test
- p2pool has _very_ verbose logging by default, it will spam a lot, no I mean A LOT in both console and in p2pool.log. Logs help testing immensely!
- I haven't tested it, but it should work properly with `logrotate`
- Wait until initial p2pool sync is finished, it shouldn't take more than 5-10 minutes. Of course it depends on your connection speed!
- p2pool has a stratum server listening on port 3333, you can connect xmrig to it now
- Run `./xmrig -o 127.0.0.1:3333`. Note that you don't need to specify wallet address for xmrig.
- xmrig should connect and start mining
- you can connect multiple miners to the same p2pool node. The more the better!
- From now on, watch your wallet to see if it gets anything
- Also check p2pool.log for any warnings and errors: `cat p2pool.log | grep -E 'WARNING|ERROR'`

## Donations

If you'd like to support further development of Monero P2Pool, you're welcome to send any amount of XMR to the following address:

```
44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg
```
