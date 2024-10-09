# Wg-easy-reverse-proxy

This project aims to do the same thing done in this video : https://www.youtube.com/watch?v=uznDiFPlvvM&t=636s&ab_channel=SpaceinvaderOne , but without tailscale because for me was too unstable on my isp , and without swag proxy because , you know installing docker and configuring the reverse  proxy by hand is hard.

#Requirements 

- Ubuntu >= 16.04
- Debian = 10-12
- for most use a vps with 1 core and 1gb of ram should be able to do around  100-500MB/s

```bash
wget https://raw.githubusercontent.com/Brazzo978/Wg-easy-reverse-proxy/refs/heads/main/wg-setup-rp.sh
chmod +x wg-setup-rp-sh
bash ./wg-setup-rp.sh
```
  
Basically what does that script do , it creates a wireguard tunnel (single client for now) and a client config that will be available on the root folder , then you can try the client config and see if it works for you , then running the script again will summon the option menù: 
1) Checks if the tunnel is running if its not it will ask you if you want to try restart it.
2) Configure a new reverse proxy ( for a single port and to the only client available )
3) Lists current reverse proxies
4) Remove one of the current reverse proxies
5) Uninstall wireguard and remove everything
6) Exit.
