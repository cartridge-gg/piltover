#!/usr/bin/env bash

sncast \
    --url http://localhost:4321 \
    --account starknet-devnet-0 \
    --wait \
    deploy \
    --class-hash 0xd68f3698fb9fa95cceb18ce452e9d1c903e96fc09f286f156f4f4a1e2d5e56 \
    --constructor-calldata 0x79f3de9fa75c7208495c088b491657cead79ca4ffc84bcb6c06d87294c58574 0x00 0x00 0x00
