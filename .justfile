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

fuzz:
    RUSTFLAGS="-C instrument-coverage" cargo fuzz run $F_TARGET

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

test:
    cargo test --features "rand" -- --nocapture



