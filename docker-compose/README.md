# Monero P2Pool Docker Compose

Run your own <b>Monero Node + P2Pool + XMRig</b> in Docker  

## Instructions

#### Install docker and docker-compose
[Install Docker](https://docs.docker.com/engine/install/)  
[Install Docker Compose](https://docs.docker.com/compose/install/)

#### Clone the P2Pool project
```
git clone --recursive https://github.com/SChernykh/p2pool
```

#### Configure your Monero address for mining rewards
```
cd p2pool/docker-compose
vi .env
```
**WALLET_ADDRESS** is the only setting that needs to be updated in that file

#### Build the docker containers
```
docker-compose build
```

#### Run the node, pool, and CPU miner
```
docker-compose up
```

#### Optional
* Open ports 18080 (Monero p2p port) and 37889 (P2Pool p2p port) in your firewall to ensure better connectivity. If you're mining from a computer behind NAT (like a router) you could consider forwarding the ports to your local machine
* An XMRig CPU miner is included by default, but you can connect additional miners to this same p2pool node using port 3333
* Configure your kernel for maximum mining performance: [XMRig RandomX Optimization Guide](https://xmrig.com/docs/miner/randomx-optimization-guide)


#### Other usefull commands
* You can **run everythng in the background** by adding the "-d" argument to the "docker-compose up" command: ```docker-compose up -d```
* You can **stop everything** with CTRL-C or ```docker-compose down```
* You can see logs when running in the background for with the "docker logs" command:  ```docker logs -f p2pool-xmrig``` or ```docker logs -f p2pool-p2pool``` or ```docker logs -f p2pool-monero```


#### Uninstall
Change to p2pool/docker-compose directory
Stop and remove all containers: ```docker-compose down```
Remove the p2pool data: ```docker volume rm p2pool```
Remove the monero data: ```docker volume rm monero```
