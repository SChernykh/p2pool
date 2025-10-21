## Running P2Pool with TOR

P2Pool has several command line options that should be used TOR setup:

- `--socks5 IP:port` to spefify your TOR proxy address (usually `127.0.0.1:9050` if you installed TOR on the same PC)
- `--no-dns` to disable all DNS queries and prevent DNS leaks. P2Pool only every does DNS requests to get a list of seed nodes, to resolve your Monero node's domain (if it's not set as an IP address), and to resolve manually added peers
- `--no-upnp` to disable UPnP requests (they are sent to your router, so use this option if you are not in your home network)
- `--onion-address` your hidden service's address (without port number). This address will be broadcasted to other peers when you mine a share in P2Pool. This is to prevent address spamming - you have to mine a real share to be able to broadcast your TOR address
- `--no-clearnet-p2p` to never connect to clearnet P2Pool nodes. This also makes sure that your P2Pool traffic doesn't exit TOR network (and is not seen/modified by the exit nodes)

## Setting up hidden service for P2Pool (Linux)

- Add these lines to your TOR config in `/etc/tor/torrc`:
	```
	HiddenServiceDir /var/lib/tor/p2pool/
	HiddenServicePort 28722 127.0.0.1:37889
	```
	Note that you must use port 28722 as hidden service's port because this is what other peers will use when trying to connect to you. Internal port (37889) should be your actual P2Pool's listening port (37889 for P2Pool-main, 37888 for P2Pool-mini, 37890 for P2Pool-nano)
- Restart TOR service:
	```
	sudo systemctl restart tor.service
	```
- If there was no errors, you should now have `/var/lib/tor/p2pool` directory with `hostname` file in it. This file will have your onion address
- Use this address in P2Pool's command line: `--onion-address ADDRESS_FROM_HOSTNAME_FILE`

## Command line example
```
./p2pool --host MONERO_NODE_IP --wallet YOUR_WALLET --socks5 127.0.0.1:9050 --no-dns --no-upnp --onion-address ADDRESS_FROM_HOSTNAME_FILE
```
