#!/usr/bin/env python

from json import load
from starkware.cairo.common.poseidon_hash import poseidon_hash_many

def main():
    with open("proof.json", "r") as f:
        proof = load(f)
    output_begin_addr = proof["public_input"]["memory_segments"]["output"]["begin_addr"]
    output_stop_ptr = proof["public_input"]["memory_segments"]["output"]["stop_ptr"]

    public_memory =  proof["public_input"]["public_memory"]
    result = {}
    for x in public_memory:
        address = x["address"]
        value = x["value"]
        result[address] = value

    output = [int(result[i], 16) for i in range(output_begin_addr, output_stop_ptr)]
    print(output)

    hash = poseidon_hash_many(output)
    print(hash)


if __name__ == "__main__":
    main()
