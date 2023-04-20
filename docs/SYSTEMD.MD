## Setting up P2Pool as a systemd service (Linux)

With this config, P2Pool will run as a service with redirected I/O. It uses `p2pool` user which you should setup beforehand.

You can execute console commands by running `echo "status" > /run/p2pool/p2pool.control`

### p2pool.service
```
[Unit]
Description=p2pool daemon
After=network-online.target systemd-modules-load.service monerod.service
Wants=network-online.target systemd-modules-load.service monerod.service
Requires=p2pool.socket

[Service]
Type=exec
Sockets=p2pool.socket
StandardInput=socket
StandardOutput=journal
StandardError=journal

# /usr/local/bin/p2pool.sh simply invokes the p2pool executable with your chosen command-line options. 
ExecStart=/usr/local/bin/p2pool.sh
TimeoutStopSec=60

# Run as p2pool:p2pool
User=p2pool
Group=p2pool

WorkingDirectory=/var/lib/p2pool

[Install]
WantedBy=multi-user.target
```

### p2pool.socket
```
# FIFO socket for controlling p2pool daemon
[Unit]
Description=Command FIFO for p2pool daemon

[Socket]
ListenFIFO=/run/p2pool/p2pool.control
DirectoryMode=0755
SocketMode=0666
SocketUser=p2pool
SocketGroup=p2pool
RemoveOnStop=true
```
