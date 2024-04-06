#!/usr/bin/env python

from json import load
from starkware.cairo.common.poseidon_hash import poseidon_hash_many

PROGRAM_HASH = 660383619500924691464496863815360321630156384984809921645828626149555048863
OUTPUT_HASH = 1844443415453774679349827339939194137492164679576351598171807045283188195521

def main():   
    hash = poseidon_hash_many([PROGRAM_HASH, OUTPUT_HASH])
    print(hash)

if __name__ == "__main__":
    main()
