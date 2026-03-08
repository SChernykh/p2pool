## Running P2Pool with I2P

P2Pool has several command-line options that should be used for I2P setup:

- `--socks5 IP:port` to specify your I2P SOCKS proxy address (usually `127.0.0.1:4447` if you are using i2pd or followed the guide below)
- `--socks5-proxy-type i2p` to specify the type of SOCKS5 proxy being used
- `--no-dns` to disable all DNS queries and prevent DNS leaks. P2Pool only ever makes DNS requests to get a list of seed nodes, to resolve your Monero node's domain (if it's not set as an IP address), and to resolve manually added peers
- `--no-upnp` to disable UPnP requests (they are sent to your router, so use this option if you are not on your home network)
- `--i2p-address` your hidden service's `.b32.i2p` address (without port number). This address will be broadcast to other peers when you mine a share in P2Pool. This is to prevent address spamming - you have to mine a real share to be able to broadcast your I2P address.
	- **Attention: this also links the I2P address with the Monero wallet you use for mining. Create a new I2P address when mining through I2P, don't use your existing addresses to avoid metadata leaks.**
- `--no-clearnet-p2p` to never connect to clearnet P2Pool nodes.

## Setting up I2P tunnels for P2Pool (i2pd on Linux)

Follow [these instructions](https://docs.i2pd.website/en/latest/user-guide/install/) to install i2pd on your system.
First, ensure both the SOCKS proxy and SAM bridge tunnels are enabled (as they should be by default). See [here](https://docs.i2pd.website/en/latest/user-guide/configuration/) for more information.

You will need to modify some lines in the `tunnels.conf` file, usually located in `/var/lib/i2pd/tunnels.conf` on Linux.
Add a server tunnel to allow inbound connections from peers:
```ini
[p2pool]
type = server
host = 127.0.0.1
port = 28723
keys = p2pool.dat
```
This will create a hidden service key in `/var/lib/i2pd/p2pool.dat`; you may want to back this up.
Please note that you **must** use the port number shown above in order for other peers to be able to find you.

Restart i2pd:
```bash
sudo systemctl restart i2pd.service
```

Get the hostname of your hidden service:
```bash
curl -s http://127.0.0.1:7070/?page=i2p_tunnels | grep -Eo "[a-zA-Z0-9./?=_%:-]*" | grep "28723"
```

The resulting `.b32.i2p` address should then be used for the `--i2p-address` command-line parameter.

## Command line example
```bash
./p2pool --host MONERO_NODE_IP --wallet YOUR_WALLET --socks5 127.0.0.1:4447 --socks5-proxy-type i2p --no-dns --no-upnp --i2p-address YOUR_I2P_ADDRESS
```
