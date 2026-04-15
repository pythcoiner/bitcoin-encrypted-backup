build:
    cargo build --release --features "cli miniscript_latest" && sudo cp target/release/beb /usr/bin/beb
bwasm:
    cargo build --target wasm32-unknown-unknown --no-default-features --features "miniscript_latest"
    cargo build --target wasm32-wasip1 --no-default-features --features "miniscript_latest"
clippy: 
    cargo clippy --features miniscript_latest
testcov:
    just clean
    RUSTFLAGS="-C instrument-coverage" cargo test --tests --features "rand"
    llvm-profdata merge -sparse default_*.profraw -o encrypted_backup.profdata
    rm -fRd *.profraw
    just showcov

showcov:
    llvm-cov show \
    --use-color --ignore-filename-regex='/.cargo/registry' \
    --instr-profile=encrypted_backup.profdata \
    -show-line-counts-or-regions \
    -show-instantiations \
    -format=html -output-dir=coverage \
    --object "target/debug/deps/$(ls target/debug/deps | grep encrypted_backup | head -n 1)"

fuzz-target target:
    RUSTFLAGS="-C instrument-coverage" cargo fuzz run {{target}}

# Run all fuzz targets in parallel for <time> seconds. Any failure
# (crash / OOM / timeout) kills all siblings. Usage: `just fuzz 1800`.
fuzz time:
    #!/usr/bin/env bash
    set -euo pipefail
    cd fuzz
    targets=(decode encode parse_deriv_paths parse_encrypted_payload parse_individual_secrets)
    pids=()
    trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
    for t in "${targets[@]}"; do
        ( cargo +nightly fuzz run "$t" -- -max_total_time={{time}} || kill -TERM 0 ) &
        pids+=($!)
    done
    wait

fcov:
    RUSTFLAGS="-C instrument-coverage" cargo fuzz coverage $F_TARGET
    just freport
freport:
    sh ./fuzz/report.sh $F_TARGET


clean:
    rm -fRd target
    rm -fRd fuzz/target
    rm -fRd fuzz/coverage
    rm -fRd fuzz/html
    rm -fRd encrypted_backup.profdata
    rm -fRd coverage
    rm -fRd *.profraw
    rm -fRd Cargo.lock

test:
    cargo test --features "rand" -- --nocapture



