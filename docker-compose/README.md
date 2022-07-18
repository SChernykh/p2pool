# Monero P2Pool Docker Compose

Run your own <b>Monero Node + P2Pool + XMRig</b> in Docker  

## Instructions

#### Install docker and docker-compose
[Install Docker](https://docs.docker.com/engine/install/)  
[Install Docker Compose](https://docs.docker.com/compose/install/)

Note: The docker compose plugin uses the command "docker compose" while the pip installed command is "docker-compose".

#### Clone the P2Pool project
```
git clone --recursive https://github.com/SChernykh/p2pool
```

#### Configure your Monero address for mining rewards
```
cd p2pool/docker-compose
./configure
```
Make sure to set your own monero **Wallet Address**.  The default is to donate mining to P2Pool development.

#### Build the docker containers
```
docker compose build --no-cache
```

#### Run the node, pool, and CPU miner (or updated configuration)
```
docker compose up
```

#### Optional
* Open ports 18080 (Monero p2p port) and 37889 (P2Pool p2p port) or 37888 (P2Pool-mini p2p port) in your firewall to ensure better connectivity. If you're mining from a computer behind NAT (like a router) you could consider forwarding the ports to your local machine
* An XMRig CPU miner is included by default, but you can connect additional miners to this same p2pool node using port 3333 (or alternate if configured) when you set it as "exposed" in the configuration
* Configure your kernel for maximum mining performance: [XMRig RandomX Optimization Guide](https://xmrig.com/docs/miner/randomx-optimization-guide)
* Many optional configurations and customizations are available by running './configure'


#### Other usefull commands
* You can **run everything in the background** by adding the "-d" argument to the "docker compose up" command: ```docker compose up -d```
* You can **stop everything** with CTRL-C or ```docker compose down```
* You can **update** by building new images with the ```--no-cache``` option.  Example: ```docker compose build --no-cache``` or just update Monero with: ```docker compose build --no-cache monero``` followed by ```docker compose up```
* You can see logs when running in the background for with the "docker compose logs" command:  ```docker compose logs -f```
* You can pause mining with: ```docker compose pause xmrig``` and resume mining with: ```docker compose unpause xmrig```
* You can disable mining with: ```docker compose stop xmrig``` and re-enable mining with: ```docker compose start xmrig```
* You can view your Server Statistics using a web browser if you enabled that feature in the configuration at: http://localhost:3380 (or alternate port as configured)


#### Uninstall
Change to p2pool/docker-compose directory <br />
Stop and remove all containers: ```docker compose down``` <br />
Remove the p2pool data: ```docker volume rm p2pool``` <br />
Remove the p2pool-mini data: ```docker volume rm p2pool-mini``` <br />
Remove the monero data: ```docker volume rm monero```
