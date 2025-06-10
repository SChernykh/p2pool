### P2Pool console commands

Command|Description
-|-
help|display list of commands
status|display p2pool status
loglevel **N**|set log level (**N** can be between 0 and 6)
addpeers **L**|**L** is a comma-separated list of IP:port of other p2pool nodes to connect to
droppeers|disconnect all currently connected peers
peers|show all currently connected peers (p2p)
workers|show all currently connected workers (stratum)
bans|show all banned IPs
hosts|show Monero hosts which were configured in the command line
next_host|switch to the next Monero host configured in the command line
outpeers **N**|set maximum number of outgoing connections (values above 50 are not recommended)
inpeers **N**|set maximum number of incoming connections (values above 50 are not recommended)
start_mining **T**|start mining (**T** is the number of threads to use, must be between 1 and 64)
stop_mining|stop mining
exit|terminate p2pool
version|show p2pool version

### Non-interactive console access

It's possible to send console commands via a local TCP connection. For this, you need to enable the API: `--data-api api --local-api`.

A sample Python script that sends console commands to P2Pool via TCP:

```
import sys
import socket
import json

with open('api/local/console', 'r') as file:
    data = json.load(file)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', data['tcp_port']))

command = data['cookie'];
command += sys.argv[1];
command += '\n';

s.sendall(command.encode('utf-8'))
s.close()
```

Run it in P2Pool's directory: `python3 ./p2pool_cmd.py status`
