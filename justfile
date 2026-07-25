# Signet — Task Runner

default:
    @echo "Signet Development Tasks"
    @echo ""
    @echo "Build:"
    @echo "  build          - Build workspace (debug)"
    @echo "  buildrelease   - Build workspace (release)"
    @echo "  check          - Check without building"
    @echo "  checknostd     - Verify core still builds without std"
    @echo ""
    @echo "Test:"
    @echo "  test           - Run all tests"
    @echo "  testcrate      - Run tests for a specific crate"
    @echo ""
    @echo "Dev:"
    @echo "  sim            - Run the airtime cost model"
    @echo "  demo           - Two nodes over a lossy channel, real keys"
    @echo "  simsweep       - Sweep loss rates, emit CSV"
    @echo "  ci             - Run fmt + clippy + tests"
    @echo "  fmt            - Format code"
    @echo "  lint           - Run clippy"
    @echo "  docs           - Build the mdbook"
    @echo "  docsserve      - Serve the mdbook with live reload"
    @echo ""
    @echo "Clean:"
    @echo "  clean          - Clean build artifacts"

# Build
build:
    cargo build --workspace

buildrelease:
    cargo build --release --workspace

check:
    cargo check --workspace

# The core crate must never grow a std dependency — it has to run on ESP32.
checknostd:
    cargo check -p signet-core --no-default-features

# Test
test:
    cargo test --workspace

testcrate crate:
    cargo test -p {{crate}}

# Simulator — the Airtime deliverable
sim *args:
    cargo run --bin signet -- sim {{args}}

simsweep:
    cargo run --release --bin signet -- sim --sweep --csv sim-out/airtime.csv

# End-to-end demo — the Protocol deliverable
demo *args:
    cargo run --bin signet -- demo {{args}}

# Dev tools
fmt:
    cargo fmt --all

fmtcheck:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

ci:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo check -p signet-core --no-default-features
    cargo test --workspace

# Docs
docs:
    cd docs && mdbook build

docsserve:
    cd docs && mdbook serve --open

# Clean
clean:
    cargo clean
