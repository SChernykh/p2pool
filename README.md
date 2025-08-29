# Monero P2Pool

Decentralized pool for Monero mining.

Pool status and monitoring pages can be found at https://p2pool.io/, https://p2pool.io/mini/ and https://p2pool.observer/, https://mini.p2pool.observer/

These are 3rd-party pages. If they are down, it doesn't mean there is a problem with P2Pool itself - it keeps mining always thanks to its decentralized nature.

### Build Status

![C/C++ CI](https://github.com/SChernykh/p2pool/actions/workflows/c-cpp.yml/badge.svg)
![test-sync](https://github.com/SChernykh/p2pool/actions/workflows/test-sync.yml/badge.svg)

![CodeQL](https://github.com/SChernykh/p2pool/actions/workflows/codeql-analysis.yml/badge.svg)
![msvc-analysis](https://github.com/SChernykh/p2pool/actions/workflows/msvc-analysis.yml/badge.svg)
![cppcheck](https://github.com/SChernykh/p2pool/actions/workflows/cppcheck.yml/badge.svg)
<a href="https://scan.coverity.com/projects/schernykh-p2pool">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/23659/badge.svg"/>
</a>
![clang-tidy](https://github.com/SChernykh/p2pool/actions/workflows/clang-tidy.yml/badge.svg)
# Contents
- [Pool mining vs Solo mining vs P2Pool mining](#pool-mining-vs-solo-mining-vs-p2pool-mining)
- [Features](#features)
- [How payouts work in P2Pool](#how-payouts-work-in-p2pool)
- [Default P2Pool parameters](#default-p2pool-parameters)
- [Monero version support](#monero-version-support)
- [How to mine on P2Pool](#how-to-mine-on-p2pool)
  - [General Considerations](#general-considerations)
  - [GUI for P2Pool](#gui-for-p2pool)
  - [Merge mining](#merge-mining)
  - [GNU/Linux](#gnulinux)
  - [Windows](#windows)
- [Build instructions](#build-instructions)
- [Reproducible builds](#reproducible-builds)
- [Donations](#donations)

## Pool mining vs Solo mining vs P2Pool mining

Here's the comparison table of the different ways of mining. While pool mining is the easiest to setup, it centralizes Monero network and pool admin gets full power over your hashrate and your unpaid funds. Solo mining is 100% independent and the best for the network. P2Pool mining has all the advantages of solo mining, but also makes regular payouts possible.

|Pool type|Payouts|Fee|Min. payout|Centralized?|Stability|Control|Setup
|-|-|-|-|-|-|-|-|
|Centralized pool|Regular|0-3%|0.001-0.01 XMR|Yes|Less stable due to pool server outages|Pool admin controls your mined funds, what you mine and can execute network attacks|Only miner software is required
|Solo|Rare|0%|0.6 XMR or more|No|As stable as your Monero node|100% under your control|Monero node + optional miner
|**P2Pool**|Regular|0%|~0.00027 XMR|No|Very stable: node failover and multiple Monero nodes are supported|100% under your control|Monero node(s) + P2Pool node(s) + optional miner(s)

## Features

* Decentralized: no central server that can be shutdown/blocked. P2Pool uses a separate blockchain to merge mine with Monero. Pool admin can't go rogue or be pressured to do an attack on the network because there is no pool admin!
* Permissionless: there is no one to decide who can mine on the pool and who can't.
* Trustless: there is no pool wallet, funds are never in custody. All pool blocks pay out to miners directly.
* PPLNS payout scheme
* **0% fee**
* **0 XMR payout fee**
* **~0.00027 XMR minimal payout**
* Fast block times, down to 1 second
* Uncle blocks are supported to avoid orphans - all your shares will be accounted for!
* Configurable PPLNS window size and block time
* Advanced mempool picking algorithm, it creates blocks with better reward than what monerod solo mining does
* Password protected private pools
* Highly reliable configurations are supported (multiple P2Pool nodes mining to the same wallet, each P2Pool node can use multiple Monero nodes and switch on the fly if an issue is detected)

## How payouts work in P2Pool

First you need to find a pool share. This share will stay in [PPLNS](https://en.wikipedia.org/wiki/Mining_pool#Pay-per-last-N-shares) window for up to 2160 pool blocks (6 hours, auto adjustable to balance payout sizes and frequency). The moment P2Pool finds a Monero block and you have at least 1 pool share in PPLNS window, you'll get a payout! Monero block reward is split between all miner wallets in PPLNS window. Each miner gets a part of block reward proportional to the total difficulty of his/her shares in PPLNS window.

**NOTE** If P2Pool doesn't have enough hashrate to find Monero blocks faster than every 6 hours on average (~15 MH/s), **not all your pool shares will result in a payout**. Even if pool hashrate is higher, bad luck can sometimes result in a share going through PPLNS window without a payout. But in the long run it will be compensated by other shares receiving multiple payouts - your payouts will average out to what you'd get with regular pool mining.

## Default P2Pool parameters

* Block time: 10 seconds
* PPLNS window: up to 2160 blocks (6 hours, auto adjustable to balance payout sizes and frequency)
* Minimum payout = Monero block reward/2160, ~0.00027 XMR

## Monero version support

- The latest Monero network upgrade happened on August 13th, 2022 (block 2,688,888).
- The latest P2Pool network upgrade happened on October 12th, 2024 at 20:00 UTC.

In order to continue mining on P2Pool, you must update both Monero and P2Pool software to the latest available versions as soon as they are released.

|Monero protocol version|Required Monero software version|Required P2Pool version
|-|-|-|
|v15, v16 (active after August 13th, 2022)|v0.18.0.0 or newer, v0.18.4.1 is recommended|v4.0 or newer

## How to mine on P2Pool

### General Considerations

- In order to mine on P2Pool, a synced Monero node using monerod v0.18.0.0 or newer is required. If you don't currently have one, you can download the [official Monero binaries](https://www.getmonero.org/downloads/), start `monerod` on your PC and wait until it's fully synced. Advanced Monero node setup instructions are [here](https://sethforprivacy.com/guides/run-a-monero-node-advanced/).
- It is highly recommended that you create a separate restricted user account (in your OS) for mining. While P2Pool has been battle-tested for a long time now, any software may have unknown bugs/vulnerabilities. 
- You have to use a primary wallet address (the one starting with `4`) for mining. Subaddresses and integrated addresses are not supported, just like with monerod solo mining.
- You can add the `--mini` parameter to your P2Pool command to connect to the **p2pool-mini** sidechain. Note that it will also change the default p2p port from 37889 to 37888.
- Check that ports 18080 (Monero p2p port) and 37889/37888 (P2Pool/P2Pool mini p2p port) are open in your firewall to ensure better connectivity. If you're mining from a computer behind NAT (like a router) you could consider forwarding the ports to your local machine.
- You can connect multiple miners to the same P2Pool node. The more the better!
- The steps below assume that you run everything on the same machine. If it's not the case, change `127.0.0.1` to appropriate IP addresses for your setup. 
- It is highly recommended to create a new mainnet wallet for P2Pool mining because **wallet addresses are public on P2Pool**.

**Wallet software compatible with P2Pool payouts**
- [Official Monero CLI and GUI v0.18.0.0 and newer](https://www.getmonero.org/downloads/)
- [Monerujo v3.0.2 "Fluorine Fermi" and newer](https://www.monerujo.io/)
- [Cake Wallet v4.4.5 and newer](https://cakewallet.com/)
- [Monero.com by Cake Wallet](https://monero.com/)
- [Feather Wallet v2.1.0 and newer](https://featherwallet.org/)
- [MyMonero](https://mymonero.com/)

### GUI for P2Pool

- [Gupax](https://github.com/hinto-janai/gupax) project aims to provide an easy to use cross-platform GUI to configure and run P2Pool & [XMRig](https://github.com/xmrig/xmrig).

### Merge mining

Merge mining is available in P2Pool since the fork that happened on October 12th, 2024. Version 4.0 or newer is required to use it.

Blockchains that will support [Merge mining RPC API](https://github.com/SChernykh/p2pool/blob/master/docs/MERGE_MINING.MD#proposed-rpc-api):
- [Townforge](https://townforge.net/) supports it in their [tmp-mm branch](https://git.townforge.net/townforge/townforge/src/branch/tmp-mm) (not released yet)
- [DarkFi](https://dark.fi/) is going to support it, but it's [not ready yet](https://github.com/darkrenaissance/darkfi/issues/244)
```
p2pool.exe --wallet YOUR_MONERO_WALLET_ADDRESS --merge-mine IP:port YOUR_WALLET_ADDRESS_ON_ANOTHER_BLOCKCHAIN
```

Blockchains that support merge mining already: [Tari](https://www.tari.com/)

Tari uses their own gRPC API and requires a different command line:
```
./p2pool --wallet YOUR_MONERO_WALLET_ADDRESS --merge-mine tari://TARI_NODE_IP:18102 TARI_WALLET_ADDRESS
```
and on the Tari side
```
./minotari_node --grpc-enabled --mining-enabled
```
TARI_NODE_IP is 127.0.0.1 if you run both on the same machine (recommended).

Merge mining is available on Tari's mainnet:
- Download [Tari suite](https://github.com/tari-project/tari/releases/latest) for your OS
- Run Minotari node and wait until in synchronizes
- Run Minotari console wallet to create a Tari wallet
- Copy the "Tari Address one-sided" from the "Receive" tab of the wallet
- Paste it into the P2Pool command line above
- Everything is ready now to start merge mining Monero and Tari!

Note that Tari will be mined in solo mode (only full Tari blocks can be mined for now). This doesn't affect P2Pool payouts - they will stay the same.

### GNU/Linux

1. Download the latest P2Pool binaries [here](https://github.com/SChernykh/p2pool/releases/latest).
   -  Alternatively, grab the latest source code for P2Pool and [build it](#build-instructions).
2. Download the latest XMRig (linux-static-x64) binary [here](https://github.com/xmrig/xmrig/releases/latest).
3. Prepare enough huge pages (each of monerod/P2Pool/XMRig needs them): 
```
sudo sysctl vm.nr_hugepages=3072
```
4. Check that ports 18080 (Monero p2p port) and 37889/37888 (P2Pool/P2Pool mini p2p port) are open in your local firewall to ensure better connectivity. 
5. Start `monerod` with the following command/options: 
```
./monerod --zmq-pub tcp://127.0.0.1:18083 --out-peers 32 --in-peers 64 --add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080 --enforce-dns-checkpointing --enable-dns-blocklist
``` 
**Note:**
The `--zmq-pub` option is required for P2Pool to work properly.

`--out-peers 32 --in-peers 64` is needed to (1) have many connections to other nodes and (2) limit incoming connection count because it can grow uncontrollably and cause problems when it goes above 1000 (open files limit in Linux). If your network connection's **upload** bandwidth is less than **10 Mbit**, use `--out-peers 8 --in-peers 16` instead.

`--add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080` is needed to have guaranteed good working nodes in your connected peers.

`--enforce-dns-checkpointing` is needed to combat the selfish mining attempts by malicious actors

`--enable-dns-blocklist` is needed to ban known bad nodes


6. Start P2Pool with the following command/options:
```
./p2pool --host 127.0.0.1 --wallet YOUR_WALLET_ADDRESS
```
7. Wait until the initial P2Pool sync is finished (shouldn't take more than 5-10 minutes).
8. Start XMRig with the following command/options:
 ```
 ./xmrig -o 127.0.0.1:3333
 ```
   - Note that you don't need to specify your wallet address for XMRig. **Wallet addresses set in XMRig config will be ignored!** 
   - To set a custom fixed difficulty for your miner (for example, 10000), instead start XMRig with the following options: 
   ```
   ./xmrig -u x+10000 -o 127.0.0.1:3333
   ```
9. XMRig should connect and start mining!

**Additional Information:** 
- For a more in-depth beginner friendly walk-through with the option of using Docker, please see SethForPrivacy's guide at: https://sethforprivacy.com/guides/run-a-p2pool-node/
- You can check the p2pool.log for any warnings or errors using the following command: 
```
grep -E 'WARNING|ERROR' p2pool.log
```
- P2Pool has verbose logging by default, you can reduce it by using "loglevel N" command where N is between 0 and 6. Default loglevel is 3.
  - You can use `logrotate` with a config like this to control logfile growth:
 ```
<path-to-logfile>
{
rotate 7
daily
missingok
delaycompress
nocreate
}
 ```

### Windows 

**Note:** *Windows SmartScreen may block incoming connections by files that are "Downloaded from the Internet". You can allow 'p2pool.exe' and 'monerod.exe' by double-clicking them, clicking "More Info", then click "Run Anyway" and then closing them immediately so you can run them from the command line. Advanced users can use the PowerShell cmdlet `Unblock-File` to remove this flag.*

1. Download the latest P2Pool binaries [here](https://github.com/SChernykh/p2pool/releases/latest).
    - Alternatively, grab the latest source code for P2Pool and [build it](#build-instructions).
2. Download the latest XMRig binary [here](https://github.com/xmrig/xmrig/releases/latest).
3. Expand the P2Pool binaries into an appropriate location (`%USERPROFILE%/bin` or `C:/bin/` are good options)
4. Expand XMRig binary into an appropriate location (the same folder as P2Pool is fine). 
5. Prepare huge pages to work properly (each of monerod/P2Pool/XMRig needs them): 
   - On Windows 10 or above, run XMRig at least once as Administrator (right-click Run As Administrator)
   - On earlier versions of Windows, you'll need to run XMRig as Administrator at least once per login.
6. Create "Monero" folder inside extracted P2Pool folder and copy Monero binaries there.
7. Open a command prompt and navigate to the folder where you extracted P2Pool.

**Note:** *When running the below commands, Windows Firewall may prompt to allow connections, click "Allow" if prompted.*

8. Start `monerod` with the following command/options: 
```
.\Monero\monerod.exe --zmq-pub tcp://127.0.0.1:18083 --out-peers 32 --in-peers 64 --add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080 --enforce-dns-checkpointing --enable-dns-blocklist
```
**Note:**
The `--zmq-pub` option is required for P2Pool to work properly.

`--out-peers 32 --in-peers 64` is needed to (1) have many connections to other nodes and (2) limit incoming connection count because it can grow uncontrollably and cause problems when it goes above 1000 (open files limit in Linux). If your network connection's **upload** bandwidth is less than **10 Mbit**, use `--out-peers 8 --in-peers 16` instead.

`--add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080` is needed to have guaranteed good working nodes in your connected peers.

`--enforce-dns-checkpointing` is needed to combat the selfish mining attempts by malicious actors

`--enable-dns-blocklist` is needed to ban known bad nodes

9. Start P2Pool with the following command/options:
```
.\p2pool.exe --host 127.0.0.1 --wallet YOUR_WALLET_ADDRESS --mini
```
10. Wait until the initial P2Pool sync is finished (shouldn't take more than 5-10 minutes).
11. Start XMRig with the following command/options:
```
.\xmrig.exe -o 127.0.0.1:3333
```
   - Note that you don't need to specify your wallet address for XMRig. **Wallet addresses set in XMRig config will be ignored!** 
   - To set a custom fixed difficulty for your miner (for example, 10000), instead start XMRig with the following options: 
     ```
     xmrig.exe -u x+10000 -o 127.0.0.1:3333
     ```
12. XMRig should connect and start mining!
13. *(Optional but highly recommended)* You can create a Quickstart by creating a batch (.bat) file with the following contents and placing it in your P2Pool directory along with `xmrig.exe`.
```
@ECHO OFF
start cmd /k %~dp0\Monero\monerod.exe --zmq-pub tcp://127.0.0.1:18083 --out-peers 32 --in-peers 64 --add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080 --enforce-dns-checkpointing --enable-dns-blocklist
ECHO Wait until the Monero daemon shows fully synced before continuing. This can take some time. Type 'status' in other window to check progress.
PAUSE
start cmd /k %~dp0\p2pool.exe --wallet YOUR_WALLET_ADDRESS --mini
ECHO Wait until the daemon shows fully synced before continuing. This can take some time.
PAUSE
%~dp0\xmrig.exe -o 127.0.0.1
```

## Build instructions
Only 64-bit builds are supported, in particular ARMv7 or older CPUs are not supported. The reason is that RandomX hashing algorithm is too slow in 32-bit mode, and P2Pool needs to check new blocks very fast to keep up with other nodes.

### Prerequisites
- cmake >= 3.10
- C++ compiler with C++17 support. GCC-8, Clang-13 and MSVC-2019 have been tested and confirmed to work, older compilers may fail to build P2Pool.

### Ubuntu 20.04

Run the following commands to install the necessary prerequisites, clone this repo, and build P2Pool locally on Ubuntu 20.04:
```
sudo apt update && sudo apt install git build-essential cmake libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev libcurl4-openssl-dev libidn2-0-dev
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### [Arch Linux](https://archlinux.org/packages/extra/x86_64/p2pool/)

```
pacman -S p2pool
```

### [Nix/NixOS](https://nixos.org)

This is a flake only project. So you have to use [nixUnstable with nix flakes](https://nixos.wiki/wiki/Flakes) to build or install P2Pool. 
The commands below use the new flake specific reference-format, so be sure to also set `ca-references` in `--experimental-features`.

Because this project has submodules which are not fixed in _nixUnstable_ yet you have to use the `nix/master` branch:
```
nix shell github:nixos/nix/master
```

Run the binary:
```
nix run git+https://github.com/SChernykh/p2pool?ref=master&submodules=1
```

Run the binary with arguments:
```
nix run git+https://github.com/SChernykh/p2pool?ref=master&submodules=1 -- --help
```

### Windows

P2Pool binary (Visual Studio Community 2019 build):
*NOTE: You need to have the "Desktop Development with C++" module installed.*
```
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
```
then open generated build\p2pool.sln in Visual Studio and build it there

Alternatively, you can select "Clone a repository" within the GUI, then select "Build" from the menu. 

### macOS

Run the following commands to install the necessary prerequisites, clone this repo, and build P2Pool locally on your Mac:
```
brew update && brew install git cmake libuv zmq libpgm curl
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.logicalcpu)
```

### FreeBSD

Run the following commands to install the necessary prerequisites, clone this repo, and build P2Pool locally on FreeBSD:
```
pkg install git cmake libuv libzmq4 curl
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make
```

### Android (Termux)

Run the following commands to install the necessary prerequisites, clone this repo, and build P2Pool locally in Termux:
```
pkg install git build-essential cmake libuv libzmq libcurl
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Reproducible builds

Starting from v4.9, P2Pool uses [reproducible builds](https://en.wikipedia.org/wiki/Reproducible_builds) to create the release binaries. This allows verification that no vulnerabilities or backdoors have been introduced during the compilation process, and that the compiled binaries correspond to the source code.

It removes the need for trust that the author or maintainer of the code is not malicious/compromised, and that the build server is not compromised.

Anyone can run the same build script on the same source code, and get the same release binaries in the end, confirming their authenticity.

Prerequisites: Ubuntu with Docker and Git installed.

Example of building v4.9 release binaries:

```
git clone --branch v4.9 --recursive https://github.com/SChernykh/p2pool
p2pool/scripts/release/build_all.sh v4.9
```
The binaries will be created in `p2pool/scripts/release` folder. First time you run it, it will take up to several hours to first build the Docker image with all the necessary tools in it. Wait until all builds are finished and then run
```
cd p2pool/scripts/release
./gen_sums.sh
```
to generate the hash sums and compare them with the official release's hash sums.

## Donations

If you'd like to support further development of Monero P2Pool, you're welcome to send any amount of XMR to the following address:

```
44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg
```

Starting from v4.6, P2Pool will also have an ability to merge mine donations for the author.

Note that this will not affect your hashrate or payouts in any way. P2Pool will always (100% of the time) keep mining to your configured Monero wallet address, but it might also use the available merge mining capacity to donate to the author.

If you merge mine yourself, your settings will take priority.

The merge mining donation runs without a donation server - there is no "phoning home" to a server, everything is done through the P2Pool's network in a decentralized way.

To opt out of this, build P2Pool with `-DWITH_MERGE_MINING_DONATION=OFF` in cmake command line. Due to the architecture of the decentralized P2Pool network, your node will still relay donation messages to other nodes even if you opted out (but it will not process them).
