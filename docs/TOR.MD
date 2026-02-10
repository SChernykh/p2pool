## Running P2Pool with TOR

P2Pool has several command-line options that should be used for TOR setup:

- `--socks5 IP:port` to specify your TOR proxy address (usually `127.0.0.1:9050` if you installed TOR on the same PC)
- `--socks5-proxy-type tor` to specify the type of SOCKS5 proxy being used
- `--no-dns` to disable all DNS queries and prevent DNS leaks. P2Pool only ever makes DNS requests to get a list of seed nodes, to resolve your Monero node's domain (if it's not set as an IP address), and to resolve manually added peers
- `--no-upnp` to disable UPnP requests (they are sent to your router, so use this option if you are not on your home network)
- `--onion-address` your hidden service's address (without port number). This address will be broadcast to other peers when you mine a share in P2Pool. This is to prevent address spamming - you have to mine a real share to be able to broadcast your TOR address.
	- **Attention: this also links the onion address with the Monero wallet you use for mining. Create a new onion address when mining through TOR, don't use your existing onion addresses to avoid meta-data leaks.**
- `--no-clearnet-p2p` to never connect to clearnet P2Pool nodes. This also makes sure that your P2Pool traffic doesn't exit the TOR network (and is not seen/modified by the exit nodes)

## Setting up a hidden service for P2Pool (Linux)

- Add these lines to your TOR config in `/etc/tor/torrc`:
	```
	HiddenServiceDir /var/lib/tor/p2pool/
	HiddenServicePort 28722 127.0.0.1:37889
	```
	Note that you must use port 28722 as the hidden service's port because this is what other peers will use when trying to connect to you. The internal port (37889) should be your actual P2Pool listening port (37889 for P2Pool-main, 37888 for P2Pool-mini, 37890 for P2Pool-nano)
- Restart the TOR service:
	```
	sudo systemctl restart tor.service
	```
- If there were no errors, you should now have the `/var/lib/tor/p2pool` directory with a `hostname` file in it. This file will contain your onion address
- Use this address in P2Pool's command line: `--onion-address ADDRESS_FROM_HOSTNAME_FILE`
- It is strongly recommended to create a new onion address for mining (see `--onion-address` remarks). This guide ensures you will be using a new onion address, assuming that you don't already have a hidden service named `p2pool`.

## Command line example
```
./p2pool --host MONERO_NODE_IP --wallet YOUR_WALLET --socks5 127.0.0.1:9050 --socks5-proxy-type tor --no-dns --no-upnp --onion-address ADDRESS_FROM_HOSTNAME_FILE
```
