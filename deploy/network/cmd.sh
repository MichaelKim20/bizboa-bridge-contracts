#!/bin/bash

set -eu

function color() {
  # Usage: color "31;5" "string"
  # Some valid values for color:
  # - 5 blink, 1 strong, 4 underlined
  # - fg: 31 red,  32 green, 33 yellow, 34 blue, 35 purple, 36 cyan, 37 white
  # - bg: 40 black, 41 red, 44 blue, 45 purple
  printf '\033[%sm%s\033[0m\n' "$@"
}

if [ "$#" -lt 1 ]; then
  color "31" "Usage: ./agora.sh PROCESS FLAGS."
  color "31" "PROCESS can be init"
  exit 1
fi

system=""
case "$OSTYPE" in
  darwin*) system="darwin" ;;
  linux*) system="linux" ;;
  msys*) system="windows" ;;
  cygwin*) system="windows" ;;
  *) exit 1 ;;
esac
readonly system

architecture=""
case $(uname -m) in
  i386)    architecture="amd64" ;;
  i686)    architecture="amd64" ;;
  x86_64)  architecture="amd64" ;;
  aarch64) architecture="amd64" ;;
  arm)     architecture="arm64" ;;
esac

dirname=${PWD##*/}
network_root="$(pwd)/network"
if [ "$dirname" = "network" ]; then
  network_root="$(pwd)"
fi

if [ "$1" = "clear-chain" ]; then

  if [ "$system" == "linux" ]; then
    sudo rm -rf "$network_root"/chain/chain
  else
    rm -rf "$network_root"/chain/chain
  fi

  mkdir -p "$network_root"/chain/chain

  cp -rf "$network_root"/chain/config/template/* "$network_root"/chain/chain/

  docker run -it -v "$network_root"/chain/chain:/data -v "$network_root"/chain/config:/config --name el-main-node --rm bosagora/agora-el-node:v2.0.1 --datadir=/data init /config/genesis.json

elif [ "$1" = "start-chain" ]; then

  docker compose -f "$network_root"/chain/docker-compose.yml up -d

elif [ "$1" = "stop-chain" ]; then

  docker compose -f "$network_root"/chain/docker-compose.yml down

fi