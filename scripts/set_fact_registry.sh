#!/usr/bin/env bash

sncast \
    --url http://localhost:4321 \
    --account starknet-devnet-0 \
    --wait \
    invoke \
    --contract-address 0x5c2b7242ae49163c0f648e78d5bd56f4c2dc2fab5cb3994602bd5ca90856726 \
    --function set_facts_registry \
    --calldata 0x2750ce5bf692d0c6688f2d2b35892f551fc3276b16f2168f4258fe435eb362a
