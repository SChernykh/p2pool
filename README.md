# Monero P2Pool

Decentralized pool for Monero mining.

Pool status and monitoring pages can be found at https://p2pool.io/ and https://p2pool.observer/

### Build status

![C/C++ CI](https://github.com/SChernykh/p2pool/actions/workflows/c-cpp.yml/badge.svg)  
![CodeQL](https://github.com/SChernykh/p2pool/actions/workflows/codeql-analysis.yml/badge.svg)  
![msvc-analysis](https://github.com/SChernykh/p2pool/actions/workflows/msvc-analysis.yml/badge.svg)  
![cppcheck](https://github.com/SChernykh/p2pool/actions/workflows/cppcheck.yml/badge.svg)  
<a href="https://scan.coverity.com/projects/schernykh-p2pool">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/23659/badge.svg"/>
</a>

## Pool mining vs Solo mining vs P2Pool mining

Here's the comparison table of the different ways of mining. While pool mining is the easiest to setup, it centralizes Monero network and pool admin gets full power over your hashrate and your unpaid funds. Solo mining is 100% independent and the best for the network. P2Pool mining has all the advantages of solo mining, but also makes regular payouts possible.

|Pool type|Payouts|Fee|Min. payout|Centralized?|Stability|Control|Setup
|-|-|-|-|-|-|-|-|
|Centralized pool|Regular|0-3%|0.001-0.01 XMR|Yes|Less stable due to pool server outages|Pool admin controls your mined funds, what you mine and can execute network attacks|Only miner software is required
|Solo|Rare|0%|0.6 XMR or more|No|As stable as your Monero node|100% under your control|Monero node + optional miner
|**P2Pool**|Regular|0%|~0.0003 XMR|No|As stable as your Monero node|100% under your control|Monero node + P2Pool node + miner

## Features

* Decentralized: no central server that can be shutdown/blocked. P2Pool uses a separate blockchain to merge mine with Monero. Pool admin can't go rogue or be pressured to do an attack on the network because there is no pool admin!
* Permissionless: there is no one to decide who can mine on the pool and who can't.
* Trustless: there is no pool wallet, funds are never in custody. All pool blocks pay out to miners immediately.
* PPLNS payout scheme
* **0% fee**
* **0 XMR payout fee**
* **~0.0003 XMR minimal payout**
* Fast block times, down to 1 second
* Uncle blocks are supported to avoid orphans - all your shares will be accounted for!
* Configurable PPLNS window size and block time
* Advanced mempool picking algorithm, it creates blocks with better reward than what monerod solo mining does
* Password protected private pools

## How PPLNS works in P2Pool

First you need to find a pool share. This share will stay in PPLNS window for 2160 pool blocks (6 hours). The moment P2Pool finds a Monero block and you have at least 1 pool share in PPLNS window, you'll get a payout! Monero block reward is split between all miner wallets in PPLNS window. Each miner gets a part of block reward proportional to the total difficulty of his/her shares in PPLNS window.

**NOTE** If P2Pool doesn't have enough hashrate to find Monero blocks faster than every 6 hours on average (~15 MH/s), **not all your pool shares will result in a payout**. Even if pool hashrate is higher, bad luck can sometimes result in a share going through PPLNS window without a payout. But in the long run it will be compensated by other shares receiving multiple payouts - your payouts will average out to what you'd get with regular pool mining.

## Default P2Pool parameters

* Block time: 10 seconds
* PPLNS window: 2160 blocks (6 hours)
* Minimum payout = Monero block reward/2160, ~0.0003 XMR

## How to mine on P2Pool

This guide assumes that you run everything on the same machine. If it's not the case, change `127.0.0.1` to appropriate IP addresses for your setup. It's highly recommended to create a new mainnet wallet for mining because **wallet addresses are public on p2pool**.

**Wallet software compatible with p2pool payouts**
- Official Monero CLI and GUI v0.17.2.3 and newer
- Monerujo v2.1.0 "Vertant" and newer
- Cake Wallet v4.2.7 and newer
- Monero.com by Cake Wallet
- Feather Wallet v1.0.0 and newer
- MyMonero

**General Considerations**

- Create a separate restricted user account for mining. p2pool is relatively new and may still have serious bugs/vulnerabilities!
- You have to use the primary wallet address for mining. Subaddresses and integrated addresses are not supported, just like with monerod solo mining.
- Check that ports 18080 (Monero p2p port) and 37889 (p2pool p2p port) are open in your firewall to ensure better connectivity. If you're mining from a computer behind NAT (like a router) you could consider forwarding the ports to your local machine.
- You can connect multiple miners to the same p2pool node. The more the better!
- Starting from p2pool v1.7, you can add `--mini` to p2pool command line to connect to the **p2pool-mini** sidechain. Note that it will also change the default p2p port from 37889 to 37888.

Step-by-step guide:

### GNU/Linux

- Download binaries from https://github.com/SChernykh/p2pool/releases/latest
- Alternatively, grab the latest source code for p2pool and build it
- Prepare enough huge pages (each of monerod/p2pool/xmrig needs them): `sudo sysctl vm.nr_hugepages=3072`
- Get xmrig (linux-static-x64) binary from https://github.com/xmrig/xmrig/releases/latest
- Check that ports 18080 (Monero p2p port) and 37889 (p2pool p2p port) are open in your firewall to ensure better connectivity
- Use the `monerod` binary v0.17.3.0 or newer
- Run `./monerod --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist` **don't forget --zmq-pub parameter in the command line**
- Run `./p2pool --host 127.0.0.1 --wallet YOUR_WALLET_ADDRESS`
- p2pool has verbose logging by default, you can reduce it by using "loglevel N" command where N is between 0 and 6. Default loglevel is 3.
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
- Wait until initial p2pool sync is finished, it shouldn't take more than 5-10 minutes, once completed xmrig should be able to connect to the stratum server on port 3333.
- Run `./xmrig -o 127.0.0.1:3333`. Note that you don't need to specify wallet address for xmrig. **Wallet address set in xmrig config will be ignored!**
- To set custom fixed difficulty for your miner (for example, 10000), run `./xmrig -u x+10000 -o 127.0.0.1:3333`
- xmrig should connect and start mining
- Also check p2pool.log for any warnings and errors: `grep -E 'WARNING|ERROR' p2pool.log`

### Windows 

*NOTE: Windows SmartScreen may block incoming connections by files that are "Downloaded from the Internet". You can allow 'p2pool.exe' and 'monerod.exe' by double-clicking them, clicking "More Info", then click "Run Anyway" and then closing them immediately so you can run them from the command line. Advanced users can use the PowerShell cmdlet `Unblock-File` to remove this flag.*

- Download p2pool binaries from https://github.com/SChernykh/p2pool/releases/latest
- Download xmrig binary from https://github.com/xmrig/xmrig/releases/latest
- Expand the p2pool binaries into an appropriate location (`%USERPROFILE%/bin` or `C:/bin/` are good options)
- Expand xmrig binary into appropriate location (same folder as p2pool is fine)
- Prepare huge pages (each of monerod/p2pool/xmrig needs them): 
  - On Windows 10 or above, run xmrig at least once as Administrator (right-click Run As Administrator)
  - On earlier versions of Windows, you'll need to run it as admin at least once per login.
- Open a command prompt and navigate to the folder where you extracted p2pool.
- *When running these commands, Windows Firewall may prompt to allow connections, click "Allow"*
- Run `.\Monero\monerod.exe --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist` *NOTE: don't forget --zmq-pub parameter in the command line*
- Run `.\p2pool.exe --host 127.0.0.1 --wallet YOUR_WALLET_ADDRESS`
- Wait until initial p2pool sync is finished, it shouldn't take more than 5-10 minutes, once completed xmrig should be able to connect to the stratum server on port 3333.
- Run `.\xmrig.exe -o 127.0.0.1:3333`. Note that you don't need to specify wallet address for xmrig. **Wallet address set in xmrig config will be ignored!**
- To set custom fixed difficulty for your miner (for example, 10000), run `xmrig.exe -u x+10000 -o 127.0.0.1:3333`
- Windows Quickstart: Create a batch (.bat) file with the following contents and place it in your p2pool directory along with xmrig.exe.
```
@ECHO OFF
start cmd /k %~dp0\Monero\monerod.exe --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist
ECHO Wait until the Monero daemon shows fully synced before continuing. This can take some time. Type 'status' in other window to check progress.
PAUSE
start cmd /k %~dp0\p2pool.exe --wallet YOUR_WALLET_ADDRESS
ECHO Wait until the daemon shows fully synced before continuing. This can take some time.
PAUSE
%~dp0\xmrig.exe -u x+30000 -o 127.0.0.1
```

## Build instructions

### Ubuntu 20.04

p2pool binary:
```
sudo apt update && sudo apt install git build-essential cmake libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Arch Linux [AUR](https://wiki.archlinux.org/title/Arch_User_Repository)

Make the package: [p2pool-git](https://aur.archlinux.org/packages/p2pool-git/)

### [Nix/NixOS](https://nixos.org)

This is a flake only project. So you have to use [nixUnstable with nix flakes](https://nixos.wiki/wiki/Flakes) to build or install p2pool. 
The commands below use the new flake specific reference-format, so be sure to also set `ca-references` in `--experimental-features`.

Because this project has submodules which are not fixed in _nixUnstable_ yet you have to use the `nix/master` branch:
```
nix shell github:nixos/nix/master
```

Run the binary:
```
nix run git+https://github.com/SChernykh/p2pool?ref=master
```

Run the binary with arguments:
```
nix run git+https://github.com/SChernykh/p2pool?ref=master -- --help
```

### macOS

p2pool binary:
```
brew update && brew install git cmake libuv zmq libpgm
git clone --recursive https://github.com/SChernykh/p2pool
cd p2pool
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.logicalcpu)
```

### Windows

p2pool binary (Visual Studio Community 2019 build):
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


## Donations

If you'd like to support further development of Monero P2Pool, you're welcome to send any amount of XMR to the following address:

```
44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg
```
