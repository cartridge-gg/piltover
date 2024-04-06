#!/usr/bin/env python

from json import load
from starkware.cairo.common.poseidon_hash import poseidon_hash_many

def main():
    with open("proof.json", "r") as f:
        proof = load(f)
    initial_pc = proof["public_input"]["memory_segments"]["program"]["begin_addr"]
    initial_fp = proof["public_input"]["memory_segments"]["execution"]["begin_addr"]

    public_memory = proof["public_input"]["public_memory"]
    result = {}
    for x in public_memory:
        address = x["address"]
        value = x["value"]
        result[address] = value

    output = [int(result[i], 16) for i in range(initial_pc, initial_fp - initial_pc - 1)]    
    hash = poseidon_hash_many(output)
    print(hash)

if __name__ == "__main__":
    main()
