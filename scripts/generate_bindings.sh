#!/bin/bash

scarb build
cargo run --bin bindgen
bash scripts/rust_fmt.sh --fix
