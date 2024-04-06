#!/usr/bin/env bash

sncast \
    --url http://localhost:4321 \
    --account starknet-devnet-0 \
    --wait \
    declare \
    --contract-name appchain
