### P2Pool command line options

```
--wallet             Wallet address to mine to. Subaddresses and integrated addresses are not supported!
--host               IP address of your Monero node, default is 127.0.0.1
--rpc-port           monerod RPC API port number, default is 18081
--zmq-port           monerod ZMQ pub port number, default is 18083 (same port as in monerod's "--zmq-pub" command line parameter)
--stratum            Comma-separated list of IP:port for stratum server to listen on
--p2p                Comma-separated list of IP:port for p2p server to listen on
--addpeers           Comma-separated list of IP:port of other p2pool nodes to connect to
--light-mode         Don't allocate RandomX dataset, saves 2GB of RAM
--loglevel           Verbosity of the log, integer number between 0 and 6
--data-dir           Path to store general p2pool files (log, cache, peer data, etc.), default is current directory
--config             Name of p2pool sidechain's config file (don't use it unless you want to mine to a different p2pool chain)
--data-api           Path to the p2pool JSON data (use it in tandem with an external web-server). Not affected by --data-dir setting!
--local-api          Enable /local/ path in api path for Stratum Server and built-in miner statistics
--stratum-api        An alias for --local-api
--no-cache           Disable p2pool.cache
--no-color           Disable colors in console output
--no-randomx         Disable internal RandomX hasher: p2pool will use RPC calls to monerod to check PoW hashes
--out-peers N        Maximum number of outgoing connections for p2p server (any value between 10 and 450)
--in-peers N         Maximum number of incoming connections for p2p server (any value between 10 and 450)
--start-mining N     Start built-in miner using N threads (any value between 1 and 64)
--mini               Connect to p2pool-mini sidechain. Note that it will also change default p2p port from 37889 to 37888
--no-autodiff        Disable automatic difficulty adjustment for miners connected to stratum (WARNING: incompatible with Nicehash and MRR)
--rpc-login          Specify username[:password] required for Monero RPC server
--socks5             Specify IP:port of a SOCKS5 proxy to use for outgoing connections
--no-dns             Disable DNS queries, use only IP addresses to connect to peers (seed node DNS will be unavailable too)
--p2p-external-port  Port number that your router uses for mapping to your local p2p port. Use it if you are behind a NAT and still want to accept incoming connections
--no-upnp            Disable UPnP port forwarding
--no-igd             An alias for --no-upnp
--upnp-stratum       Port forward Stratum port (it's not forwarded by default)
--merge-mine         IP:port and wallet address for another blockchain to merge mine with
--version            Print p2pool's version and build details
--tls-cert file      Load TLS certificate chain from "file" in the PEM format
--tls-cert-key file  Load TLS certificate private key from "file" in the PEM format
--no-stratum-http    Disable HTTP on Stratum ports
```

### Example command line

```
p2pool.exe --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet YOUR_WALLET_ADDRESS --stratum 0.0.0.0:3333 --p2p 0.0.0.0:37889
```

### Multiple backup hosts

You can have multiple hosts in command line. If P2Pool detects that the host it's currently using is down or stuck, it will cycle through hosts until it finds a working one. It will not switch back as long as the current host it found is working.

Each new host uses RPC and zmq-pub port numbers from the previous host (or default 18081/18083 if none were specified). Note that `--rpc-login` is not copied from the previous host, you must specify it for each host that has username/password.

In this example, you have local Monero host running on ports 18081/18083 (RPC/zmq-pub), and several backup hosts running on ports 18089/18084.


```
p2pool.exe --host 127.0.0.1 --host node.monerodevs.org --rpc-port 18089 --zmq-port 18084 --host node2.monerodevs.org --host node.richfowler.net --wallet YOUR_WALLET_ADDRESS
```

### Merge mining

Merge mining will be available in P2Pool after the fork on October 12th, 2024. Version 4.0 or newer is required to use it.

- Blockchains that will support [Merge mining RPC API](https://github.com/SChernykh/p2pool/blob/master/docs/MERGE_MINING.MD#proposed-rpc-api)
  - [Townforge](https://townforge.net/) supports it in their [tmp-mm branch](https://git.townforge.net/townforge/townforge/src/branch/tmp-mm) (not released yet)
  - [DarkFi](https://dark.fi/) is going to support it, but it's [not ready yet](https://github.com/darkrenaissance/darkfi/issues/244)
  ```
  p2pool.exe --wallet YOUR_MONERO_WALLET_ADDRESS --merge-mine IP:port YOUR_WALLET_ADDRESS_ON_ANOTHER_BLOCKCHAIN
  ```

- [Tari](https://www.tari.com/) uses their own gRPC API and requires a different command line:
  ```
  ./p2pool --wallet YOUR_MONERO_WALLET_ADDRESS --merge-mine tari://IP:port TARI_WALLET_ADDRESS
  ```
  and on the Tari side
  ```
  ./minotari_node --grpc-enabled --mining-enabled
  ```
  Merge mining is available for testing in Tari's [latest release](https://github.com/tari-project/tari/releases) (Esmeralda testnet).

### TLS

Starting from v4.1, P2Pool supports SSL/TLS connections to its Stratum port. Port 443 can also be safely used for Stratum connections since v4.1 - P2Pool will detect HTTP requests and respond to them.

All `--tls...` parameters are optional. If they are not provided, P2Pool will generate a self-signed certificate upon startup.

If you want to use your own certificate, please refer to your certificate provider's documentation (or OpenSSL documentation) on how to generate the appropriate PEM files.

Note that you need to use certificate files and `--tls...` parameters to be able to use certificate pinning in XMRig miners that connect to your P2Pool instance.

`--tls-cert` and `--tls-cert-key` parameters must always be used together.
