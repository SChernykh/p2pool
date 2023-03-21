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
--config             Name of the p2pool config file
--data-api           Path to the p2pool JSON data (use it in tandem with an external web-server)
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
```

### Example command line

p2pool.exe --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet YOUR_WALLET_ADDRESS --stratum 0.0.0.0:3333 --p2p 0.0.0.0:37889
