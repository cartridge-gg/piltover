#!/usr/bin/env bash

sncast \
    --url http://localhost:4321 \
    --account starknet-devnet-0 \
    --wait \
    invoke \
    --contract-address 0x5c2b7242ae49163c0f648e78d5bd56f4c2dc2fab5cb3994602bd5ca90856726 \
    --function set_program_info \
    --calldata 660383619500924691464496863815360321630156384984809921645828626149555048863 0
