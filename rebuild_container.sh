#!/bin/bash
#Script to rebuild docker container
#Also hacky SSL cert renew

sudo docker rm -f sneaky_proxy
sudo docker image prune -af
sudo docker compose build
sudo docker compose up -d
