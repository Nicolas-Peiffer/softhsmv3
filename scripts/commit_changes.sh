#!/usr/bin/env bash
# commit_changes.sh
# Commits and pushes the final v0.4.24 fixes via Pull Request.

set -e

# Validate formatting
echo "Validating Rust format..."
cd /Users/ericamador/antigravity/softhsmv3/rust
cargo fmt || { echo "Run cargo fmt!"; exit 1; }

echo "Running E2E tests..."
cd /Users/ericamador/antigravity/softhsmv3/build
brew install cppunit || true
export CPATH="$(brew --prefix)/include"
export LIBRARY_PATH="$(brew --prefix)/lib"
cmake ..
make
ctest --output-on-failure || { echo "Tests failed!"; exit 1; }

cd /Users/ericamador/antigravity/softhsmv3

# Check for uncommitted changes
git status

# Create branch
git checkout -b fix/close-remaining-issues-v0424

# Stage files
git add src/lib/P11Objects.cpp src/lib/P11Objects.h
git add rust/Cargo.toml
git add CHANGELOG.md

# Commit
git commit -m "feat: resolve gaps 37, 38, 50 for v0.4.24 release

- C_CreateObject automatically extracts CKA_PUBLIC_KEY_INFO from X.509 CKA_VALUE via OpenSSL
- Bumped Rust crate edition to 2024
- Updated CHANGELOG.md for #37, #38, #50
- Verified CKA_ALWAYS_AUTHENTICATE enforcement in SoftHSM_sign.cpp"

# Push and PR
git push -u origin fix/close-remaining-issues-v0424

# Assuming gh is installed, create the PR
gh pr create --title "feat: resolve gaps 37, 38, 50 for v0.4.24 release" --body "Resolves #37, confirms #38, and resolves #50. This PR finalizes the remaining compliance gaps for v0.4.24."

echo "All done! Issue #50 can be closed via the PR."
