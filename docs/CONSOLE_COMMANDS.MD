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
